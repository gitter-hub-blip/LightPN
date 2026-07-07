package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// echoServer stands in for an internet target.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

// startSocks runs an ExitController's SOCKS server on a random port and
// returns its address.
func startSocks(t *testing.T, ec *ExitController) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ec.Serve(ctx, addr)
	// wait for it to bind
	waitDial(t, addr)
	return addr
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never came up", addr)
}

func socksRoundTrip(t *testing.T, socksAddr, target string, payload string) string {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial via socks: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

// TestSocksDirect: with no upstream, the entry SOCKS reaches the target
// directly.
func TestSocksDirect(t *testing.T) {
	target := echoServer(t)
	ec, _ := NewExitController(quietLog(), "")
	entry := startSocks(t, ec)
	if got := socksRoundTrip(t, entry, target.Addr().String(), "hello-direct"); got != "hello-direct" {
		t.Fatalf("echo = %q", got)
	}
}

// TestSocksChainedThroughExit: entry SOCKS (A) with an upstream pointing at
// an exit SOCKS (B) must relay A -> B -> target. This is the exact data
// path of 客户端 -> A -> (overlay) -> B -> 公网.
func TestSocksChainedThroughExit(t *testing.T) {
	target := echoServer(t)

	// B: exit node's SOCKS, egresses directly.
	exitEC, _ := NewExitController(quietLog(), "")
	exitAddr := startSocks(t, exitEC)

	// A: entry SOCKS, upstream = B.
	entryEC, _ := NewExitController(quietLog(), "")
	entryAddr := startSocks(t, entryEC)
	entryEC.SetLinkExit("link-1", exitAddr)

	if got := socksRoundTrip(t, entryAddr, target.Addr().String(), "via-exit"); got != "via-exit" {
		t.Fatalf("echo through exit chain = %q", got)
	}

	// Withdraw the exit → A reverts to direct, still works.
	entryEC.ClearByLink("link-1")
	if entryEC.up.Load() != nil {
		t.Fatal("upstream should be nil after ClearByLink")
	}
	if got := socksRoundTrip(t, entryAddr, target.Addr().String(), "back-direct"); got != "back-direct" {
		t.Fatalf("echo after revert = %q", got)
	}
}

// TestExitOverrideIgnoresHub: --exit-via pins the upstream; hub-driven
// SetLinkExit/Reconcile must not change it.
func TestExitOverrideIgnoresHub(t *testing.T) {
	target := echoServer(t)
	exitEC, _ := NewExitController(quietLog(), "")
	exitAddr := startSocks(t, exitEC)

	entryEC, err := NewExitController(quietLog(), exitAddr) // pinned
	if err != nil {
		t.Fatal(err)
	}
	entryAddr := startSocks(t, entryEC)
	entryEC.ClearByLink("anything") // should be a no-op under override
	entryEC.Reconcile(map[string]string{})
	if entryEC.up.Load() == nil {
		t.Fatal("override upstream was cleared by hub events")
	}
	if got := socksRoundTrip(t, entryAddr, target.Addr().String(), "pinned"); got != "pinned" {
		t.Fatalf("echo = %q", got)
	}
}
