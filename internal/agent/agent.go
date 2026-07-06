// Package agent implements the LightPN edge agent: it keeps the mTLS
// control channel to the hub, drives kernel WireGuard on instruction, and
// reports system metrics with each heartbeat.
package agent

import (
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

	connMu sync.Mutex
	conn   net.Conn
}

// Run connects (with exponential backoff) and serves sessions forever,
// until kicked. Every reconnect goes through the §5.3 register/reconcile
// convergence path.
func (a *Agent) Run() error {
	warmupCPU()
	backoff := time.Second
	for {
		err := a.session()
		if errors.Is(err, ErrKicked) {
			return err
		}
		if err != nil {
			a.Log.Warn("session ended", "err", err)
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

	// Fresh ephemeral WG material for this session (invariant 2). The
	// device is rebuilt so no peer from a previous run survives.
	pubkey, port, err := a.WG.Init(a.ID.OverlayIP, a.ID.OverlayCIDR, a.WGPort)
	if err != nil {
		return fmt.Errorf("wireguard init: %w", err)
	}

	if err := a.register(conn, pubkey, port); err != nil {
		return err
	}
	a.Log.Info("registered with hub", "control", a.ID.ControlAddr, "wg_port", port)

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
		a.Log.Info("peer applied", "type", env.Type, "peer", spec.PeerName, "endpoint", spec.Endpoint, "err", err)
		return a.ack(conn, env.ID, err)

	case proto.TypePeerRemove:
		var d proto.PeerRemoveData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return a.ack(conn, env.ID, err)
		}
		err := a.WG.RemovePeer(d.WGPubkey)
		a.Log.Info("peer removed", "link", d.LinkID, "err", err)
		return a.ack(conn, env.ID, err)

	case proto.TypeRotateWG:
		a.ack(conn, env.ID, nil)
		a.Log.Info("rotating WG key on hub request")
		// Reuse the full convergence path: drop the session; reconnect
		// regenerates the key and re-registers (§5.7).
		return errors.New("rotate_wg: reconnecting with fresh key")

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
