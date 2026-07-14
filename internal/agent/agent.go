// Package agent implements the LightPN edge agent: it keeps the mTLS
// control channel to the hub, drives kernel WireGuard on instruction, and
// reports system metrics with each heartbeat.
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
	"github.com/oklog/ulid/v2"
)

// Version is the agent build version reported in register.
const Version = "0.1.0"

// ErrKicked signals a hub-ordered permanent shutdown.
var ErrKicked = errors.New("kicked by hub")

// Agent is the long-running edge process.
type Agent struct {
	ID     *Identity
	WG     WGManager
	Log    *slog.Logger
	WGPort int // desired listen port (default 51820)

	HeartbeatPeriod time.Duration

	// Exit, when non-nil, is the local exit SOCKS5 proxy. SocksListen is
	// the local bind address; SocksPort is the overlay-reachable port
	// reported to the hub so other nodes may egress through this one.
	Exit        *ExitController
	SocksListen string
	SocksPort   int

	connMu sync.Mutex
	conn   net.Conn

	// Current WG identity: set once by Run, replaced only by an explicit
	// rotate_wg. Read/written only on the Run→session goroutine.
	wgPub        string
	wgListenPort int
}

// stableSession is how long a session must survive before the reconnect
// backoff resets: failures days apart shouldn't inherit an old penalty.
const stableSession = time.Minute

// Run connects (with exponential backoff) and serves sessions forever,
// until kicked. Every reconnect goes through the §5.3 register/reconcile
// convergence path.
func (a *Agent) Run() error {
	warmupCPU()

	// The WG device lives for the whole process: control-channel loss must
	// not disturb an established data plane (§4 invariant 1). The key pair
	// is still ephemeral — generated here, never persisted (invariant 2).
	// Only rotate_wg, kick, or a process restart change it.
	pubkey, port, err := a.WG.Init(a.ID.OverlayIP, a.ID.OverlayCIDR, a.WGPort)
	if err != nil {
		return fmt.Errorf("wireguard init: %w", err)
	}
	a.wgPub, a.wgListenPort = pubkey, port

	// Start the exit SOCKS listener once the overlay device exists, so a
	// bind to the overlay IP succeeds. It lives for the whole process;
	// upstream switching (not re-binding) handles subsequent peer events.
	if a.Exit != nil && a.SocksListen != "" {
		go func() {
			if err := a.Exit.Serve(context.Background(), a.SocksListen); err != nil {
				a.Log.Error("exit SOCKS server stopped", "err", err)
			}
		}()
	}

	backoff := time.Second
	for {
		started := time.Now()
		err := a.session()
		if errors.Is(err, ErrKicked) {
			return err
		}
		if err != nil {
			a.Log.Warn("session ended", "err", err)
		}
		if time.Since(started) >= stableSession {
			backoff = time.Second
		}
		// Exponential backoff: 1s → 60s, ±20% jitter.
		jitter := 0.8 + 0.4*rand.Float64()
		sleep := time.Duration(float64(backoff) * jitter)
		a.Log.Info("reconnecting", "in", sleep.Round(time.Millisecond))
		time.Sleep(sleep)
		backoff *= 2
		if backoff > time.Minute {
			backoff = time.Minute
		}
	}
}

func (a *Agent) session() error {
	tlsCfg, err := a.ID.TLSConfig()
	if err != nil {
		return err
	}
	// TCP keepalive detects silently dead paths; the hub actively closes
	// sessions it considers dead, so no application-level read timeout.
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", a.ID.ControlAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial hub: %w", err)
	}
	defer conn.Close()
	a.connMu.Lock()
	a.conn = conn
	a.connMu.Unlock()

	// Re-register with the existing WG identity: a control reconnect only
	// converges peer state (register + reconcile), never the data plane.
	if err := a.register(conn, a.wgPub, a.wgListenPort); err != nil {
		return err
	}
	a.Log.Info("registered with hub", "control", a.ID.ControlAddr, "wg_port", a.wgListenPort)

	// Heartbeat loop.
	stop := make(chan struct{})
	defer close(stop)
	go a.heartbeatLoop(conn, stop)

	// Read loop: hub pushes; register_ack already consumed. The hub may
	// legitimately stay silent for long periods.
	conn.SetReadDeadline(time.Time{})
	for {
		env, err := proto.ReadFrame(conn)
		if err != nil {
			return err
		}
		if err := a.dispatch(conn, env); err != nil {
			return err
		}
	}
}

// register sends the session registration and applies the reconciliation
// list from register_ack.
func (a *Agent) register(conn net.Conn, pubkey string, port int) error {
	env, err := proto.NewEnvelope(proto.TypeRegister, ulid.Make().String(), proto.RegisterData{
		WGPubkey:     pubkey,
		WGPort:       port,
		AgentVersion: Version,
		OS:           runtime.GOOS + "/" + runtime.GOARCH,
		SocksPort:    a.SocksPort,
	})
	if err != nil {
		return err
	}
	if err := a.write(conn, env); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := proto.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read register_ack: %w", err)
	}
	if resp.Type == proto.TypeError {
		var e proto.ErrorData
		json.Unmarshal(resp.Data, &e)
		if e.Code == proto.ErrCertRevoked || e.Code == proto.ErrAuthFailed {
			// Identity is dead; keep retrying is pointless but destroying
			// local state automatically would be surprising. Log loudly.
			a.Log.Error("hub rejected identity", "code", e.Code, "msg", e.Msg)
		}
		return fmt.Errorf("register rejected: %s (%s)", e.Msg, e.Code)
	}
	if resp.Type != proto.TypeRegisterAck {
		return fmt.Errorf("unexpected register response %q", resp.Type)
	}
	var ack proto.RegisterAckData
	if err := json.Unmarshal(resp.Data, &ack); err != nil {
		return err
	}
	if err := a.WG.Reconcile(ack.PeersExpected); err != nil {
		return fmt.Errorf("reconcile peers: %w", err)
	}
	if a.Exit != nil {
		exits := map[string]string{}
		for _, s := range ack.PeersExpected {
			if s.Exit && s.ExitAddr != "" {
				exits[s.LinkID] = s.ExitAddr
			}
		}
		a.Exit.Reconcile(exits)
	}
	a.Log.Info("reconciled peers", "count", len(ack.PeersExpected))
	return nil
}

func (a *Agent) heartbeatLoop(conn net.Conn, stop <-chan struct{}) {
	t := time.NewTicker(a.HeartbeatPeriod)
	defer t.Stop()
	send := func() {
		wgStatus, err := a.WG.Status()
		if err != nil {
			a.Log.Warn("wg status", "err", err)
			wgStatus = nil
		}
		env, err := proto.NewEnvelope(proto.TypeHeartbeat, ulid.Make().String(), proto.HeartbeatData{
			TS:  time.Now().Unix(),
			Sys: collectSys(),
			WG:  wgStatus,
		})
		if err != nil {
			return
		}
		if err := a.write(conn, env); err != nil {
			conn.Close() // unblocks the read loop
		}
	}
	send()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			send()
		}
	}
}

// write serializes frame writes (heartbeat loop and dispatch ACKs share
// the connection).
func (a *Agent) write(conn net.Conn, env *proto.Envelope) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return proto.WriteFrame(conn, env)
}

func (a *Agent) dispatch(conn net.Conn, env *proto.Envelope) error {
	switch env.Type {
	case proto.TypePeerAdd, proto.TypePeerUpdate:
		var spec proto.PeerSpec
		if err := json.Unmarshal(env.Data, &spec); err != nil {
			return a.ack(conn, env.ID, err)
		}
		var err error
		if env.Type == proto.TypePeerAdd {
			err = a.WG.AddPeer(spec)
		} else {
			err = a.WG.UpdatePeer(spec)
		}
		// Track the exit designation carried by this peer (empty ExitAddr
		// or Exit=false clears it for this link).
		if a.Exit != nil && err == nil {
			if spec.Exit && spec.ExitAddr != "" {
				a.Exit.SetLinkExit(spec.LinkID, spec.ExitAddr)
			} else {
				a.Exit.SetLinkExit(spec.LinkID, "")
			}
		}
		a.Log.Info("peer applied", "type", env.Type, "peer", spec.PeerName, "endpoint", spec.Endpoint, "exit", spec.Exit, "err", err)
		return a.ack(conn, env.ID, err)

	case proto.TypePeerRemove:
		var d proto.PeerRemoveData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return a.ack(conn, env.ID, err)
		}
		err := a.WG.RemovePeer(d.WGPubkey)
		if a.Exit != nil {
			a.Exit.ClearByLink(d.LinkID)
		}
		a.Log.Info("peer removed", "link", d.LinkID, "err", err)
		return a.ack(conn, env.ID, err)

	case proto.TypeRotateWG:
		a.ack(conn, env.ID, nil)
		pub, err := a.WG.Rotate()
		if err != nil {
			return fmt.Errorf("rotate_wg: %w", err)
		}
		a.wgPub = pub
		a.Log.Info("rotated WG key on hub request")
		// Drop the session: reconnecting re-registers the new pubkey and
		// reconciles peers (§5.7); the hub pushes peer_update to the others.
		return errors.New("rotate_wg: re-registering with fresh key")

	case proto.TypeRotateCert:
		var d proto.RotateCertData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return a.ack(conn, env.ID, err)
		}
		err := a.ID.UpdateCert(d.CertPEM)
		a.Log.Info("certificate rotated", "err", err)
		return a.ack(conn, env.ID, err)

	case proto.TypeKick:
		var d proto.KickData
		json.Unmarshal(env.Data, &d)
		a.Log.Warn("kicked by hub", "reason", d.Reason)
		// §5.7: clear all kernel peers, destroy identity, exit.
		if err := a.WG.Teardown(); err != nil {
			a.Log.Error("teardown", "err", err)
		}
		if err := a.ID.Destroy(); err != nil {
			a.Log.Error("destroy identity", "err", err)
		}
		return ErrKicked

	case proto.TypeError:
		var e proto.ErrorData
		json.Unmarshal(env.Data, &e)
		a.Log.Warn("hub error", "code", e.Code, "msg", e.Msg)
		return nil

	default:
		a.Log.Warn("unknown message type", "type", env.Type)
		return nil
	}
}

func (a *Agent) ack(conn net.Conn, id string, opErr error) error {
	d := proto.AckData{OK: opErr == nil}
	if opErr != nil {
		d.Err = opErr.Error()
	}
	env, err := proto.NewEnvelope(proto.TypeAck, id, d)
	if err != nil {
		return err
	}
	return a.write(conn, env)
}

// DefaultDataDir is the agent identity directory.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("ProgramData") + "\\lightpn\\identity"
	}
	return "/var/lib/lightpn/identity"
}
