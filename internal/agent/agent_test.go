package agent

// Control-plane / data-plane decoupling tests: a control reconnect must
// re-register with the *same* WG identity (no Init, no key change); only an
// explicit rotate_wg changes the key, and only kick tears the device down.

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/pki"
	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// fakeWG tracks lifecycle calls without touching any kernel.
type fakeWG struct {
	mu          sync.Mutex
	initCalls   int
	rotateCalls int
	teardowns   int
	pub         string
}

func testKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (w *fakeWG) Init(_, _ string, port int) (string, int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initCalls++
	w.pub = testKey()
	return w.pub, port, nil
}

func (w *fakeWG) Rotate() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateCalls++
	w.pub = testKey()
	return w.pub, nil
}

func (w *fakeWG) Teardown() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.teardowns++
	return nil
}

func (w *fakeWG) counts() (init, rotate, teardown int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.initCalls, w.rotateCalls, w.teardowns
}

func (w *fakeWG) Reconcile([]proto.PeerSpec) error      { return nil }
func (w *fakeWG) AddPeer(proto.PeerSpec) error          { return nil }
func (w *fakeWG) UpdatePeer(proto.PeerSpec) error       { return nil }
func (w *fakeWG) RemovePeer(string) error               { return nil }
func (w *fakeWG) Status() ([]proto.WGPeerStatus, error) { return nil, nil }

// hubSession is one accepted control connection with its register data.
type hubSession struct {
	conn net.Conn
	reg  proto.RegisterData
}

// waitFrame reads frames until one of the wanted type arrives (heartbeats
// interleave on the same connection).
func (s *hubSession) waitFrame(t *testing.T, typ string) *proto.Envelope {
	t.Helper()
	s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		env, err := proto.ReadFrame(s.conn)
		if err != nil {
			t.Fatalf("waiting for %s: %v", typ, err)
		}
		if env.Type == typ {
			return env
		}
	}
}

// startFakeHub runs a minimal mTLS control endpoint that answers register
// with an empty reconcile list and hands each session to the test.
func startFakeHub(t *testing.T) (addr string, sessions <-chan *hubSession, id *Identity) {
	t.Helper()
	caDir := t.TempDir()
	ca, err := pki.LoadOrCreate(caDir)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, err := ca.IssueServer(caDir, []string{"lightpn-hub"})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	keyPEM, csrPEM, err := pki.NewIdentityKey("test-node")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.SignCSR(csrPEM, "node-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	id = &Identity{
		Dir:           t.TempDir(),
		NodeID:        "node-test",
		ControlAddr:   ln.Addr().String(),
		OverlayIP:     "100.100.0.2/32",
		OverlayCIDR:   "100.100.0.0/24",
		CAFingerprint: ca.Fingerprint(),
	}
	if err := id.Save(keyPEM, certPEM, ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	// The TLS SNI is lightpn-hub while we dial an IP; Identity.TLSConfig
	// already pins ServerName, so nothing else is needed.

	ch := make(chan *hubSession, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				env, err := proto.ReadFrame(conn)
				if err != nil || env.Type != proto.TypeRegister {
					conn.Close()
					return
				}
				var reg proto.RegisterData
				if err := json.Unmarshal(env.Data, &reg); err != nil {
					conn.Close()
					return
				}
				ack, _ := proto.NewEnvelope(proto.TypeRegisterAck, env.ID, proto.RegisterAckData{
					NodeID: "node-test", OverlayIP: "100.100.0.2/32",
				})
				if err := proto.WriteFrame(conn, ack); err != nil {
					conn.Close()
					return
				}
				ch <- &hubSession{conn: conn, reg: reg}
			}(conn)
		}
	}()
	return ln.Addr().String(), ch, id
}

func waitSession(t *testing.T, ch <-chan *hubSession) *hubSession {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(15 * time.Second):
		t.Fatal("agent never (re)connected")
		return nil
	}
}

// TestControlReconnectKeepsDataPlane covers the §4 invariants end to end on
// the agent side: reconnect keeps the key, rotate_wg replaces it, kick
// tears down.
func TestControlReconnectKeepsDataPlane(t *testing.T) {
	_, sessions, id := startFakeHub(t)
	wg := &fakeWG{}
	a := &Agent{
		ID: id, WG: wg, WGPort: 51820,
		HeartbeatPeriod: time.Hour,
		Log:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	runErr := make(chan error, 1)
	go func() { runErr <- a.Run() }()

	// Session 1: initial connect.
	s1 := waitSession(t, sessions)
	firstPub := s1.reg.WGPubkey
	if init, _, _ := wg.counts(); init != 1 {
		t.Fatalf("Init calls after first connect = %d, want 1", init)
	}

	// Drop the control connection: the agent must reconnect with the SAME
	// WG identity and must not reinitialize the device.
	s1.conn.Close()
	s2 := waitSession(t, sessions)
	if s2.reg.WGPubkey != firstPub {
		t.Fatalf("pubkey changed across control reconnect: %q -> %q", firstPub, s2.reg.WGPubkey)
	}
	if init, rot, _ := wg.counts(); init != 1 || rot != 0 {
		t.Fatalf("after reconnect: Init=%d Rotate=%d, want 1/0", init, rot)
	}

	// rotate_wg: the agent must ack, rotate in place, and re-register with
	// the new key.
	rot, _ := proto.NewEnvelope(proto.TypeRotateWG, "rot-1", struct{}{})
	if err := proto.WriteFrame(s2.conn, rot); err != nil {
		t.Fatal(err)
	}
	s2.waitFrame(t, proto.TypeAck)
	s3 := waitSession(t, sessions)
	if s3.reg.WGPubkey == firstPub {
		t.Fatal("pubkey did not change after rotate_wg")
	}
	if init, rotN, _ := wg.counts(); init != 1 || rotN != 1 {
		t.Fatalf("after rotate: Init=%d Rotate=%d, want 1/1", init, rotN)
	}

	// kick: teardown + identity destroyed + Run returns ErrKicked.
	kick, _ := proto.NewEnvelope(proto.TypeKick, "kick-1", proto.KickData{Reason: "test"})
	if err := proto.WriteFrame(s3.conn, kick); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runErr:
		if !errors.Is(err, ErrKicked) {
			t.Fatalf("Run returned %v, want ErrKicked", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not exit after kick")
	}
	if _, _, td := wg.counts(); td != 1 {
		t.Fatalf("Teardown calls = %d, want 1", td)
	}
	if _, err := os.Stat(id.Dir); !os.IsNotExist(err) {
		t.Fatalf("identity dir still exists after kick (stat err=%v)", err)
	}
}
