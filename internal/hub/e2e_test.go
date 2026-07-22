package hub

// End-to-end control-channel tests covering the §12 risk matrix:
// enroll → register reconcile → link matchmaking → agent restart with a new
// ephemeral pubkey (peers must receive peer_update) → node delete cascade.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/pki"
	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

func startHub(t *testing.T) *Hub {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(dir + "/hub.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ca, err := pki.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.DataDir = dir
	cfg.ControlAddr = "127.0.0.1:0"
	h, err := New(cfg, store, ca, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go h.ServeControl(stop)
	for i := 0; i < 100; i++ {
		if h.ControlBoundAddr() != "" {
			return h
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("control listener never bound")
	return nil
}

// fakeAgent drives the wire protocol like a real agent.
type fakeAgent struct {
	t         *testing.T
	hub       *Hub
	nodeID    string
	keyPEM    string
	certPEM   string
	caPEM     string
	socksPort int  // reported in register (exit SOCKS advertisement)
	noConf    bool // when true, ignore conf_get (timeout testing)

	conn net.Conn

	mu     sync.Mutex
	pushes []*proto.Envelope // peer_add/update/remove/kick received
	closed bool
}

func enrollAgent(t *testing.T, h *Hub, hostname string) *fakeAgent {
	t.Helper()
	plaintext, _, err := h.Store.CreateToken(15*time.Minute, "", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := pki.NewIdentityKey(hostname)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", h.ControlBoundAddr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	env, _ := proto.NewEnvelope(proto.TypeEnroll, NewULID(), proto.EnrollData{
		Token: plaintext, Hostname: hostname, CSRPEM: csrPEM,
	})
	if err := proto.WriteFrame(conn, env); err != nil {
		t.Fatal(err)
	}
	resp, err := proto.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != proto.TypeEnrollAck {
		t.Fatalf("enroll response = %s: %s", resp.Type, resp.Data)
	}
	var ack proto.EnrollAckData
	json.Unmarshal(resp.Data, &ack)
	return &fakeAgent{
		t: t, hub: h, nodeID: ack.NodeID,
		keyPEM: keyPEM, certPEM: ack.CertPEM, caPEM: ack.CAPEM,
	}
}

// connect establishes the mTLS session and registers with the given pubkey.
// It starts a background reader that auto-ACKs pushes and records them.
func (f *fakeAgent) connect(pubkey string, port int) proto.RegisterAckData {
	f.t.Helper()
	cert, err := tls.X509KeyPair([]byte(f.certPEM), []byte(f.keyPEM))
	if err != nil {
		f.t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(f.caPEM))
	caCert, _ := x509.ParseCertificate(block.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	conn, err := tls.Dial("tcp", f.hub.ControlBoundAddr(), &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "lightpn-hub",
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.conn = conn
	f.mu.Lock()
	f.closed = false
	f.mu.Unlock()

	env, _ := proto.NewEnvelope(proto.TypeRegister, NewULID(), proto.RegisterData{
		WGPubkey: pubkey, WGPort: port, AgentVersion: "test", OS: "test",
		SocksPort: f.socksPort,
	})
	if err := proto.WriteFrame(conn, env); err != nil {
		f.t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := proto.ReadFrame(conn)
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Type != proto.TypeRegisterAck {
		f.t.Fatalf("register response = %s: %s", resp.Type, resp.Data)
	}
	var ack proto.RegisterAckData
	json.Unmarshal(resp.Data, &ack)
	go f.readLoop(conn)
	return ack
}

func (f *fakeAgent) readLoop(conn net.Conn) {
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		env, err := proto.ReadFrame(conn)
		if err != nil {
			f.mu.Lock()
			f.closed = true
			f.mu.Unlock()
			return
		}
		f.mu.Lock()
		f.pushes = append(f.pushes, env)
		f.mu.Unlock()
		switch env.Type {
		case proto.TypePeerAdd, proto.TypePeerUpdate, proto.TypePeerRemove, proto.TypeRotateWG:
			ackEnv, _ := proto.NewEnvelope(proto.TypeAck, env.ID, proto.AckData{OK: true})
			proto.WriteFrame(conn, ackEnv)
		case proto.TypeExitWGSet:
			var spec proto.ExitWGSpec
			json.Unmarshal(env.Data, &spec)
			res, _ := proto.NewEnvelope(proto.TypeExitWGState, env.ID, proto.ExitWGStateData{
				Enabled: spec.Enabled, Pubkey: "EXITPUB_" + f.nodeID[:4], Port: spec.Port,
			})
			proto.WriteFrame(conn, res)
		case proto.TypeConfGet:
			if f.noConf {
				break
			}
			res, _ := proto.NewEnvelope(proto.TypeConfResult, env.ID, proto.ConfResultData{
				WG: proto.ConfWG{Iface: "lightpn0", Pubkey: "PUBKEY_TEST", ListenPort: 51820},
				Files: []proto.ConfFile{
					{Tool: "xray", Path: "/usr/local/etc/xray/config.json", Content: `{"id":"uuid-here"}`},
				},
			})
			proto.WriteFrame(conn, res)
		}
	}
}

// waitPush blocks until a push of the given type arrives (or times out).
func (f *fakeAgent) waitPush(typ string, timeout time.Duration) *proto.Envelope {
	f.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		for _, p := range f.pushes {
			if p.Type == typ {
				f.mu.Unlock()
				return p
			}
		}
		f.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("no %s push within %s", typ, timeout)
	return nil
}

func (f *fakeAgent) clearPushes() {
	f.mu.Lock()
	f.pushes = nil
	f.mu.Unlock()
}

func (f *fakeAgent) heartbeat(wg []proto.WGPeerStatus) {
	env, _ := proto.NewEnvelope(proto.TypeHeartbeat, NewULID(), proto.HeartbeatData{
		TS: time.Now().Unix(), Sys: proto.SysMetrics{CPUPct: 1}, WG: wg,
	})
	if err := proto.WriteFrame(f.conn, env); err != nil {
		f.t.Fatal(err)
	}
}

func TestEnrollRegisterLinkFlow(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")

	ackA := a.connect("PUBKEY_A_1", 51820)
	if ackA.NodeID != a.nodeID || len(ackA.PeersExpected) != 0 {
		t.Fatalf("bad register_ack: %+v", ackA)
	}
	b.connect("PUBKEY_B_1", 51821)

	// Create the link: both online → both must receive peer_add.
	l, err := h.CreateLink(a.nodeID, b.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	pa := a.waitPush(proto.TypePeerAdd, 3*time.Second)
	pb := b.waitPush(proto.TypePeerAdd, 3*time.Second)

	var specA, specB proto.PeerSpec
	json.Unmarshal(pa.Data, &specA)
	json.Unmarshal(pb.Data, &specB)
	if specA.WGPubkey != "PUBKEY_B_1" || specB.WGPubkey != "PUBKEY_A_1" {
		t.Fatalf("wrong pubkeys pushed: a got %s, b got %s", specA.WGPubkey, specB.WGPubkey)
	}
	// Invariant 5: endpoint IP must come from the control connection, port
	// from the self-declared WG port.
	if host, port, _ := net.SplitHostPort(specA.Endpoint); host != "127.0.0.1" || port != "51821" {
		t.Fatalf("endpoint = %s, want 127.0.0.1:51821", specA.Endpoint)
	}

	// After both ACKs but before any handshake, the link is degraded-or-
	// pending, never active.
	waitFor(t, 3*time.Second, func() bool {
		l2, _ := h.Store.GetLink(l.ID)
		st := h.LinkStatus(l2)
		return st == "degraded" || st == "pending"
	})

	// A handshake reported via heartbeat flips it to active.
	a.heartbeat([]proto.WGPeerStatus{{
		PeerNodeID: b.nodeID, LastHandshakeTS: time.Now().Unix(), RxBytes: 1, TxBytes: 1,
	}})
	waitFor(t, 3*time.Second, func() bool {
		l2, _ := h.Store.GetLink(l.ID)
		return h.LinkStatus(l2) == "active"
	})
}

// TestAgentRestartPushesPeerUpdate is the highest-risk path (§5.3): an agent
// re-registers with a fresh ephemeral key and every online linked peer must
// receive peer_update carrying the new pubkey.
func TestAgentRestartPushesPeerUpdate(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")
	a.connect("PUBKEY_A_1", 51820)
	b.connect("PUBKEY_B_1", 51820)
	if _, err := h.CreateLink(a.nodeID, b.nodeID); err != nil {
		t.Fatal(err)
	}
	a.waitPush(proto.TypePeerAdd, 3*time.Second)
	b.waitPush(proto.TypePeerAdd, 3*time.Second)
	b.clearPushes()

	// "Restart" agent A: drop the connection, reconnect with a new key.
	a.conn.Close()
	a.clearPushes()
	ack := a.connect("PUBKEY_A_2", 51820)

	// A's register_ack must reconcile the existing link.
	if len(ack.PeersExpected) != 1 || ack.PeersExpected[0].WGPubkey != "PUBKEY_B_1" {
		t.Fatalf("reconcile list wrong: %+v", ack.PeersExpected)
	}
	// B must get peer_update with A's new key.
	pu := b.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var spec proto.PeerSpec
	json.Unmarshal(pu.Data, &spec)
	if spec.WGPubkey != "PUBKEY_A_2" {
		t.Fatalf("peer_update pubkey = %s, want PUBKEY_A_2", spec.WGPubkey)
	}
}

// TestLinkCreateWhileOffline: link created while one side is offline stays
// pending and is completed via register reconcile when it comes online.
func TestLinkCreateWhileOffline(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")
	a.connect("PUBKEY_A_1", 51820)
	// B never connected. Link must be created as pending, no crash.
	l, err := h.CreateLink(a.nodeID, b.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if st := h.LinkStatus(l); st != "pending" {
		t.Fatalf("link status = %s, want pending", st)
	}
	// B comes online: its register_ack must contain A, and A must get the
	// completed pair pushed.
	a.clearPushes()
	ack := b.connect("PUBKEY_B_1", 51820)
	if len(ack.PeersExpected) != 1 || ack.PeersExpected[0].WGPubkey != "PUBKEY_A_1" {
		t.Fatalf("offline side reconcile wrong: %+v", ack.PeersExpected)
	}
	pu := a.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var spec proto.PeerSpec
	json.Unmarshal(pu.Data, &spec)
	if spec.WGPubkey != "PUBKEY_B_1" {
		t.Fatalf("a got pubkey %s, want PUBKEY_B_1", spec.WGPubkey)
	}
}

// TestDeleteNodeCascade: delete must remove links, push peer_remove to the
// other side, kick the target and revoke its certificate.
func TestDeleteNodeCascade(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")
	a.connect("PUBKEY_A_1", 51820)
	b.connect("PUBKEY_B_1", 51820)
	h.CreateLink(a.nodeID, b.nodeID)
	a.waitPush(proto.TypePeerAdd, 3*time.Second)
	b.waitPush(proto.TypePeerAdd, 3*time.Second)

	if err := h.DeleteNode(b.nodeID); err != nil {
		t.Fatal(err)
	}
	// A gets peer_remove for B's key.
	pr := a.waitPush(proto.TypePeerRemove, 3*time.Second)
	var rd proto.PeerRemoveData
	json.Unmarshal(pr.Data, &rd)
	if rd.WGPubkey != "PUBKEY_B_1" {
		t.Fatalf("peer_remove pubkey = %s, want PUBKEY_B_1", rd.WGPubkey)
	}
	// B gets kicked.
	b.waitPush(proto.TypeKick, 3*time.Second)
	// Links are gone.
	links, _ := h.Store.ListLinks()
	if len(links) != 0 {
		t.Fatalf("links not cleaned: %d left", len(links))
	}
	// B's cert is revoked: reconnecting must fail at the app layer.
	waitFor(t, 5*time.Second, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.closed
	})
	cert, _ := tls.X509KeyPair([]byte(b.certPEM), []byte(b.keyPEM))
	block, _ := pem.Decode([]byte(b.caPEM))
	caCert, _ := x509.ParseCertificate(block.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	conn, err := tls.Dial("tcp", h.ControlBoundAddr(), &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "lightpn-hub",
	})
	if err != nil {
		return // rejected at handshake: also acceptable
	}
	defer conn.Close()
	env, _ := proto.NewEnvelope(proto.TypeRegister, NewULID(), proto.RegisterData{WGPubkey: "X", WGPort: 1})
	proto.WriteFrame(conn, env)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := proto.ReadFrame(conn)
	if err != nil {
		return // connection dropped: fine
	}
	if resp.Type != proto.TypeError {
		t.Fatalf("revoked node got %s, want error", resp.Type)
	}
	var e proto.ErrorData
	json.Unmarshal(resp.Data, &e)
	if e.Code != proto.ErrCertRevoked && e.Code != proto.ErrAuthFailed {
		t.Fatalf("error code = %s", e.Code)
	}
}

func TestTokenReuseRejected(t *testing.T) {
	h := startHub(t)
	plaintext, _, _ := h.Store.CreateToken(15*time.Minute, "", time.Now().Unix())

	enrollOnce := func() (string, error) {
		keyPEM, csrPEM, _ := pki.NewIdentityKey("dup")
		_ = keyPEM
		conn, err := tls.Dial("tcp", h.ControlBoundAddr(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		env, _ := proto.NewEnvelope(proto.TypeEnroll, NewULID(), proto.EnrollData{
			Token: plaintext, Hostname: "dup", CSRPEM: csrPEM,
		})
		proto.WriteFrame(conn, env)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := proto.ReadFrame(conn)
		if err != nil {
			return "", err
		}
		return resp.Type, nil
	}
	typ, err := enrollOnce()
	if err != nil || typ != proto.TypeEnrollAck {
		t.Fatalf("first enroll: %s %v", typ, err)
	}
	typ, err = enrollOnce()
	if err != nil || typ != proto.TypeError {
		t.Fatalf("second enroll: %s %v, want error", typ, err)
	}
}

// TestLinkExitPushesExitSpec: designating B as a link's exit must push
// peer_update to A carrying Exit=true and ExitAddr = B_overlay:B_socks,
// and only to A (B stays a plain peer). Clearing it reverts A.
func TestLinkExitPushesExitSpec(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")
	b.socksPort = 1080 // B advertises an exit SOCKS
	a.connect("PUBKEY_A_1", 51820)
	b.connect("PUBKEY_B_1", 51820)
	l, err := h.CreateLink(a.nodeID, b.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	a.waitPush(proto.TypePeerAdd, 3*time.Second)
	b.waitPush(proto.TypePeerAdd, 3*time.Second)
	a.clearPushes()
	b.clearPushes()

	// Set B as the exit node.
	if _, err := h.SetLinkExit(l.ID, b.nodeID); err != nil {
		t.Fatal(err)
	}
	pu := a.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var specA proto.PeerSpec
	json.Unmarshal(pu.Data, &specA)
	if !specA.Exit {
		t.Fatalf("A's spec should have Exit=true: %+v", specA)
	}
	bNode, _ := h.Store.GetNode(b.nodeID)
	wantAddr := bNode.OverlayIP + ":1080"
	if specA.ExitAddr != wantAddr {
		t.Fatalf("ExitAddr = %q, want %q", specA.ExitAddr, wantAddr)
	}
	// B must NOT be told to exit via A.
	puB := b.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var specB proto.PeerSpec
	json.Unmarshal(puB.Data, &specB)
	if specB.Exit {
		t.Fatalf("B's spec should not have Exit set: %+v", specB)
	}

	// Clearing the exit reverts A to Exit=false.
	a.clearPushes()
	if _, err := h.SetLinkExit(l.ID, ""); err != nil {
		t.Fatal(err)
	}
	pu2 := a.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var specA2 proto.PeerSpec
	json.Unmarshal(pu2.Data, &specA2)
	if specA2.Exit {
		t.Fatalf("after clear, A's spec should have Exit=false: %+v", specA2)
	}
}

// TestExitRequiresSocksAdvertisement: if the designated exit node never
// advertised a SOCKS port, no Exit flag is sent (fail safe to direct).
func TestExitRequiresSocksAdvertisement(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	b := enrollAgent(t, h, "edge-b")
	// B does NOT set socksPort.
	a.connect("PUBKEY_A_1", 51820)
	b.connect("PUBKEY_B_1", 51820)
	l, _ := h.CreateLink(a.nodeID, b.nodeID)
	a.waitPush(proto.TypePeerAdd, 3*time.Second)
	b.waitPush(proto.TypePeerAdd, 3*time.Second)
	a.clearPushes()

	if _, err := h.SetLinkExit(l.ID, b.nodeID); err != nil {
		t.Fatal(err)
	}
	pu := a.waitPush(proto.TypePeerUpdate, 3*time.Second)
	var spec proto.PeerSpec
	json.Unmarshal(pu.Data, &spec)
	if spec.Exit {
		t.Fatalf("exit must not activate without SOCKS advertisement: %+v", spec)
	}
}

// TestToolConfRequest: the panel-triggered conf_get round trip. An online
// agent's conf_result is returned to the API caller; an offline node errors
// immediately; a silent agent errors with ErrConfTimeout after the deadline.
func TestToolConfRequest(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")
	a.connect("PUBKEY_A_1", 51820)

	data, err := h.RequestToolConf(a.nodeID, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var res proto.ConfResultData
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.WG.Pubkey != "PUBKEY_TEST" || len(res.Files) != 1 || res.Files[0].Tool != "xray" {
		t.Fatalf("bad conf result: %+v", res)
	}

	// Offline node: fail fast, no waiter left behind.
	b := enrollAgent(t, h, "edge-b")
	if _, err := h.RequestToolConf(b.nodeID, time.Second); err == nil {
		t.Fatal("offline node must error")
	}

	// Silent agent: timeout, and the waiter map must be cleaned up.
	c := enrollAgent(t, h, "edge-c")
	c.noConf = true
	c.connect("PUBKEY_C_1", 51820)
	if _, err := h.RequestToolConf(c.nodeID, 300*time.Millisecond); err != ErrConfTimeout {
		t.Fatalf("want ErrConfTimeout, got %v", err)
	}
	h.mu.Lock()
	left := len(h.confWait)
	h.mu.Unlock()
	if left != 0 {
		t.Fatalf("confWait not cleaned up: %d left", left)
	}
}

// TestExitWGFlow: direct-connect WG lifecycle. register_ack always carries
// the desired state; enabling pushes exitwg_set to the online agent whose
// exitwg_status pubkey is stored; client IPs allocate sequentially with
// duplicate pubkeys rejected; a reconnect reconciles the full spec.
func TestExitWGFlow(t *testing.T) {
	h := startHub(t)
	a := enrollAgent(t, h, "edge-a")

	// Never configured: register_ack still carries a disabled spec.
	ack := a.connect("PUBKEY_A_1", 51820)
	if ack.ExitWG == nil || ack.ExitWG.Enabled {
		t.Fatalf("register_ack exitwg = %+v, want disabled spec", ack.ExitWG)
	}

	// Enable + push: the agent's exitwg_status pubkey must land in the store.
	if _, err := h.Store.SetExitWG(a.nodeID, true, 51899); err != nil {
		t.Fatal(err)
	}
	if err := h.PushExitWG(a.nodeID); err != nil {
		t.Fatal(err)
	}
	push := a.waitPush(proto.TypeExitWGSet, 3*time.Second)
	var spec proto.ExitWGSpec
	json.Unmarshal(push.Data, &spec)
	if !spec.Enabled || spec.Port != 51899 || spec.CIDR == "" {
		t.Fatalf("bad exitwg_set: %+v", spec)
	}
	wantPub := "EXITPUB_" + a.nodeID[:4]
	waitFor(t, 3*time.Second, func() bool {
		cfg, _ := h.Store.GetExitWG(a.nodeID)
		return cfg != nil && cfg.Pubkey == wantPub
	})

	// Client devices: sequential IPs from .2 (server holds .1), dup rejected.
	p1, err := h.Store.AddExitWGPeer(a.nodeID, "phone", "CLIENTPUB_1", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := h.Store.AddExitWGPeer(a.nodeID, "laptop", "CLIENTPUB_2", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if p1.IP != "10.99.0.2/32" || p2.IP != "10.99.0.3/32" {
		t.Fatalf("client IPs = %s, %s", p1.IP, p2.IP)
	}
	if _, err := h.Store.AddExitWGPeer(a.nodeID, "dup", "CLIENTPUB_1", time.Now().Unix()); err == nil {
		t.Fatal("duplicate client pubkey must be rejected")
	}
	// Freed IP is reused.
	if err := h.Store.DeleteExitWGPeer(a.nodeID, p1.ID); err != nil {
		t.Fatal(err)
	}
	p3, err := h.Store.AddExitWGPeer(a.nodeID, "tablet", "CLIENTPUB_3", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if p3.IP != "10.99.0.2/32" {
		t.Fatalf("freed IP not reused: %s", p3.IP)
	}

	// Reconnect: register_ack reconciles the enabled spec with both peers.
	a.conn.Close()
	a.clearPushes()
	ack = a.connect("PUBKEY_A_2", 51820)
	if ack.ExitWG == nil || !ack.ExitWG.Enabled || len(ack.ExitWG.Peers) != 2 {
		t.Fatalf("reconnect exitwg = %+v, want enabled with 2 peers", ack.ExitWG)
	}

	// Disable converges too.
	a.clearPushes()
	if _, err := h.Store.SetExitWG(a.nodeID, false, 51899); err != nil {
		t.Fatal(err)
	}
	if err := h.PushExitWG(a.nodeID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, p := range a.pushes {
			if p.Type == proto.TypeExitWGSet {
				var s proto.ExitWGSpec
				json.Unmarshal(p.Data, &s)
				return !s.Enabled
			}
		}
		return false
	})
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
