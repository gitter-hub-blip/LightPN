package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ExitController is the agent-local exit SOCKS5 proxy. A censorship-
// circumvention server (Reality/VLESS, etc.) points its outbound at this
// proxy; the agent then decides, per hub matchmaking, whether that traffic
// egresses directly to the internet or is chained through a peer's overlay
// SOCKS (i.e. exits via that peer).
//
// The upstream is swapped atomically on peer_add/peer_update/peer_remove, so
// the circumvention software's config never changes. Because it targets the
// peer's *overlay* address (stable per NodeID), it is unaffected by the
// ephemeral WG key churn underneath — LightPN self-heals the tunnel.
type ExitController struct {
	log *slog.Logger

	// up holds the current upstream: nil means direct egress.
	up atomic.Pointer[upstream]

	// override, when set (via --exit-via), pins the upstream and makes the
	// controller ignore hub-driven exit specs.
	override *upstream

	// exits maps link ID -> the peer's exit SOCKS address, for links the
	// hub has marked with an exit. Keyed by link ID because peer_remove
	// identifies the withdrawal only by link. With the single-exit model
	// there is at most one entry, but the map keeps the design general.
	mu    sync.Mutex
	exits map[string]string
}

type upstream struct {
	addr   string // "100.100.0.9:1080"
	dialer proxy.Dialer
}

func newUpstream(addr string) (*upstream, error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, directDialer{})
	if err != nil {
		return nil, err
	}
	return &upstream{addr: addr, dialer: d}, nil
}

// NewExitController builds a controller. overrideAddr (may be "") pins the
// upstream for manual testing and disables hub-driven switching.
func NewExitController(log *slog.Logger, overrideAddr string) (*ExitController, error) {
	ec := &ExitController{log: log, exits: map[string]string{}}
	if overrideAddr != "" {
		up, err := newUpstream(overrideAddr)
		if err != nil {
			return nil, err
		}
		ec.override = up
		ec.up.Store(up)
		log.Info("exit upstream pinned by --exit-via", "addr", overrideAddr)
	}
	return ec, nil
}

// SetLinkExit records/clears a link's exit designation and recomputes the
// active upstream. exitAddr == "" clears it.
func (ec *ExitController) SetLinkExit(linkID, exitAddr string) {
	if ec.override != nil {
		return // manual override wins
	}
	ec.mu.Lock()
	if exitAddr == "" {
		delete(ec.exits, linkID)
	} else {
		ec.exits[linkID] = exitAddr
	}
	ec.mu.Unlock()
	ec.recompute("switched")
}

// ClearByLink drops any exit tied to linkID (on peer_remove / link delete).
func (ec *ExitController) ClearByLink(linkID string) {
	if ec.override != nil {
		return
	}
	ec.mu.Lock()
	_, had := ec.exits[linkID]
	delete(ec.exits, linkID)
	ec.mu.Unlock()
	if had {
		ec.recompute("link withdrawn")
	}
}

// Reconcile replaces the full exit set from a register_ack peer list,
// keyed by link ID.
func (ec *ExitController) Reconcile(byLink map[string]string) {
	if ec.override != nil {
		return
	}
	ec.mu.Lock()
	ec.exits = map[string]string{}
	for id, addr := range byLink {
		ec.exits[id] = addr
	}
	ec.mu.Unlock()
	ec.recompute("reconciled")
}

// recompute chooses the active upstream (at most one, single-exit model).
func (ec *ExitController) recompute(why string) {
	ec.mu.Lock()
	var chosen string
	for _, addr := range ec.exits {
		chosen = addr
		break
	}
	ec.mu.Unlock()
	if chosen == "" {
		if ec.up.Swap(nil) != nil {
			ec.log.Info("exit egress: direct", "why", why)
		}
		return
	}
	up, err := newUpstream(chosen)
	if err != nil {
		ec.log.Error("build exit upstream", "addr", chosen, "err", err)
		return
	}
	ec.up.Store(up)
	ec.log.Info("exit egress: via peer", "addr", chosen, "why", why)
}

// dial routes a CONNECT to the current upstream (or direct).
func (ec *ExitController) dial(network, addr string) (net.Conn, error) {
	if up := ec.up.Load(); up != nil {
		return up.dialer.Dial(network, addr)
	}
	return directDialer{}.Dial(network, addr)
}

type directDialer struct{}

func (directDialer) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, 15*time.Second)
}

// Serve runs the SOCKS5 listener until ctx is done. The initial bind is
// retried briefly: when binding to the overlay IP, the kernel may not have
// finished applying the address the instant WG.Init returns.
func (ec *ExitController) Serve(ctx context.Context, listenAddr string) error {
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", listenAddr); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err != nil {
		return err
	}
	ec.log.Info("exit SOCKS5 listening", "addr", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go ec.handle(conn)
	}
}

// handle implements a minimal SOCKS5 server: no-auth, CONNECT only.
func (ec *ExitController) handle(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))

	target, err := socksHandshake(client)
	if err != nil {
		ec.log.Debug("socks handshake", "err", err)
		return
	}
	remote, err := ec.dial("tcp", target)
	if err != nil {
		// 0x05 = connection refused
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	// success reply with a zero BND.ADDR (clients ignore it here)
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	relay(client, remote)
}

// socksHandshake performs method negotiation and reads a CONNECT request,
// returning the target "host:port". Only no-auth + CONNECT are supported.
func socksHandshake(c net.Conn) (string, error) {
	buf := make([]byte, 262)
	// VER, NMETHODS
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", errors.New("not socks5")
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return "", err
	}
	// reply: no authentication required
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	// request: VER CMD RSV ATYP ...
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", errors.New("bad request version")
	}
	if buf[1] != 0x01 { // CONNECT only
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", errors.New("unsupported command")
	}
	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return "", err
		}
		host = string(buf[:l])
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", errors.New("unsupported address type")
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// relay copies bytes both ways until either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}
