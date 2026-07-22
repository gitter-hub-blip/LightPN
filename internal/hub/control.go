package hub

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// ackRef ties an in-flight push to the link/side it will confirm.
type ackRef struct {
	linkID string
	side   string // "a" | "b"
}

// session is one live agent control connection.
type session struct {
	node *Node
	conn net.Conn
	out  chan *proto.Envelope

	registered   bool
	agentVersion string
	osStr        string
	lastHB       int64
	hbWG         []proto.WGPeerStatus
	pendingAcks  map[string]ackRef // envelope id -> link ack target

	closeOnce sync.Once
	done      chan struct{}
}

// send enqueues an envelope on the ordered outbound queue. If the queue is
// full the session is torn down: the agent reconnects and reconciles via
// register, which is the designed recovery path.
func (s *session) send(env *proto.Envelope) {
	select {
	case s.out <- env:
	default:
		s.close()
	}
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

// ServeControl runs the mTLS control listener. Client certs are verified
// against the CA when present; connections without one may only enroll.
func (h *Hub) ServeControl(stop <-chan struct{}) error {
	certPath, keyPath, err := h.CA.IssueServer(h.Cfg.DataDir, serverHosts(h.Cfg))
	if err != nil {
		return err
	}
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.CA.Cert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		// Enrollment connections carry no client cert; everything else must.
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", h.Cfg.ControlAddr, tlsCfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.controlBound = ln.Addr().String()
	h.mu.Unlock()
	h.Log.Info("control channel listening", "addr", ln.Addr())
	go func() {
		<-stop
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				h.Log.Warn("accept", "err", err)
				continue
			}
		}
		go h.handleConn(conn.(*tls.Conn))
	}
}

func serverHosts(cfg Config) []string {
	hosts := []string{"lightpn-hub", "localhost", "127.0.0.1"}
	if cfg.PublicAddr != "" {
		if host, _, err := net.SplitHostPort(cfg.PublicAddr); err == nil {
			hosts = append(hosts, host)
		} else {
			hosts = append(hosts, cfg.PublicAddr)
		}
	}
	return hosts
}

func (h *Hub) handleConn(conn *tls.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		h.handleEnroll(conn)
		return
	}
	cert := state.PeerCertificates[0]
	nodeID := cert.Subject.CommonName
	serial := cert.SerialNumber.Text(16)
	if h.isRevoked(serial) {
		h.sendError(conn, proto.ErrCertRevoked, "certificate revoked")
		return
	}
	node, err := h.Store.GetNode(nodeID)
	if err != nil || node.Revoked || node.CertSerial != serial {
		h.sendError(conn, proto.ErrAuthFailed, "unknown or revoked node")
		return
	}
	h.runSession(conn, node)
}

func (h *Hub) sendError(conn net.Conn, code, msg string) {
	env, err := proto.NewEnvelope(proto.TypeError, NewULID(), proto.ErrorData{Code: code, Msg: msg})
	if err == nil {
		proto.WriteFrame(conn, env)
	}
}

// ---- enrollment ----

// enrollAllowed rate-limits the unauthenticated enroll path per source IP.
func (h *Hub) enrollAllowed(ip string) bool {
	h.enrollMu.Lock()
	defer h.enrollMu.Unlock()
	if h.enrollTries == nil {
		h.enrollTries = map[string][]time.Time{}
	}
	now := time.Now()
	kept := h.enrollTries[ip][:0]
	for _, t := range h.enrollTries[ip] {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	h.enrollTries[ip] = kept
	if len(kept) >= 5 {
		return false
	}
	h.enrollTries[ip] = append(kept, now)
	return true
}

func (h *Hub) handleEnroll(conn *tls.Conn) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !h.enrollAllowed(remoteIP) {
		h.sendError(conn, proto.ErrAuthFailed, "rate limited")
		return
	}
	env, err := proto.ReadFrame(conn)
	if err != nil {
		return
	}
	if env.V != proto.Version {
		h.sendError(conn, proto.ErrVersionUnsupported, "unsupported protocol version")
		return
	}
	if env.Type != proto.TypeEnroll {
		h.sendError(conn, proto.ErrAuthFailed, "client certificate required")
		return
	}
	var d proto.EnrollData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		h.sendError(conn, proto.ErrInternal, "bad enroll payload")
		return
	}
	now := time.Now().Unix()
	switch err := h.Store.ConsumeToken(d.Token, now); {
	case errors.Is(err, ErrTokenExpired):
		h.sendError(conn, proto.ErrTokenExpired, "token expired")
		return
	case errors.Is(err, ErrTokenUsed):
		h.sendError(conn, proto.ErrTokenUsed, "token already used")
		return
	case errors.Is(err, ErrNotFound):
		h.sendError(conn, proto.ErrAuthFailed, "unknown token")
		return
	case err != nil:
		h.sendError(conn, proto.ErrInternal, "token check failed")
		return
	}

	overlayIP, err := h.Store.AllocateIP(h.Cfg.OverlayCIDR, h.Cfg.IPCooldown(), now)
	if err != nil {
		h.sendError(conn, proto.ErrIPAMExhausted, err.Error())
		return
	}
	nodeID := NewULID()
	certTTL := time.Duration(h.Cfg.CertTTLDays) * 24 * time.Hour
	certPEM, serial, err := h.CA.SignCSR(d.CSRPEM, nodeID, certTTL)
	if err != nil {
		h.sendError(conn, proto.ErrInternal, "CSR rejected")
		return
	}
	name := d.Hostname
	if name == "" {
		name = nodeID
	}
	node := &Node{ID: nodeID, Name: name, OverlayIP: overlayIP, CertSerial: serial, CreatedAt: now}
	if err := h.Store.CreateNode(node); err != nil {
		h.sendError(conn, proto.ErrInternal, "node create failed")
		return
	}

	controlAddr := h.Cfg.PublicAddr
	if controlAddr == "" {
		controlAddr = conn.LocalAddr().String()
	}
	ack, err := proto.NewEnvelope(proto.TypeEnrollAck, env.ID, proto.EnrollAckData{
		NodeID:      nodeID,
		CertPEM:     certPEM,
		CAPEM:       h.CA.CertPEM(),
		OverlayIP:   overlayIP + "/32",
		OverlayCIDR: h.Cfg.OverlayCIDR,
		ControlAddr: controlAddr,
	})
	if err != nil {
		return
	}
	proto.WriteFrame(conn, ack)
	h.Log.Info("node enrolled", "node", nodeID, "name", name, "ip", overlayIP)
	h.publish("enrolled", map[string]any{"node_id": nodeID, "name": name})
}

// ---- authenticated session ----

func (h *Hub) runSession(conn *tls.Conn, node *Node) {
	s := &session{
		node:        node,
		conn:        conn,
		out:         make(chan *proto.Envelope, 64),
		pendingAcks: map[string]ackRef{},
		done:        make(chan struct{}),
		lastHB:      time.Now().Unix(),
	}
	h.mu.Lock()
	if old := h.sessions[node.ID]; old != nil {
		old.close() // one live session per node
	}
	h.sessions[node.ID] = s
	delete(h.gcDone, node.ID)
	h.mu.Unlock()
	defer h.dropSession(s)

	go h.sessionWriter(s)
	h.Log.Info("session up", "node", node.ID, "name", node.Name)
	h.publish("node_status", map[string]any{"node_id": node.ID, "status": "online"})

	for {
		// Liveness: no frame within DeadAfter → mark offline, close.
		conn.SetReadDeadline(time.Now().Add(h.Cfg.DeadAfter()))
		env, err := proto.ReadFrame(conn)
		if err != nil {
			return
		}
		if env.V != proto.Version {
			h.sendError(conn, proto.ErrVersionUnsupported, "unsupported protocol version")
			return
		}
		switch env.Type {
		case proto.TypeRegister:
			h.handleRegister(s, env)
		case proto.TypeHeartbeat:
			h.handleHeartbeat(s, env)
		case proto.TypeAck:
			h.handleAck(s, env)
		case proto.TypeConfResult:
			h.handleConfResult(s, env)
		default:
			h.sendError(conn, proto.ErrUnknownType, "unknown message type "+env.Type)
		}
	}
}

func (h *Hub) sessionWriter(s *session) {
	for {
		select {
		case <-s.done:
			return
		case env := <-s.out:
			s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(s.conn, env); err != nil {
				s.close()
				return
			}
		}
	}
}

func (h *Hub) dropSession(s *session) {
	s.close()
	h.mu.Lock()
	if h.sessions[s.node.ID] == s {
		delete(h.sessions, s.node.ID)
	}
	h.mu.Unlock()
	h.Store.TouchNode(s.node.ID, time.Now().Unix())
	h.Log.Info("session down", "node", s.node.ID)
	h.publish("node_status", map[string]any{"node_id": s.node.ID, "status": "offline"})
}

// handleRegister processes §5.3: record the ephemeral WG material, answer
// with the full expected-peer list, and push the new pubkey to all online
// linked peers. This is the convergence path for every restart scenario.
func (h *Hub) handleRegister(s *session, env *proto.Envelope) {
	var d proto.RegisterData
	if err := json.Unmarshal(env.Data, &d); err != nil || d.WGPubkey == "" || d.WGPort <= 0 || d.WGPort > 65535 {
		h.sendError(s.conn, proto.ErrInternal, "bad register payload")
		return
	}
	remoteIP, _, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	// Invariant 5: endpoint IP comes from the control connection source
	// address; the agent may only declare its WG listen and exit SOCKS ports.
	ident := wgIdent{pubkey: d.WGPubkey, port: d.WGPort, ip: remoteIP, socksPort: d.SocksPort}

	links, err := h.Store.LinksOfNode(s.node.ID)
	if err != nil {
		h.sendError(s.conn, proto.ErrInternal, "link lookup failed")
		return
	}

	h.mu.Lock()
	h.lastWG[s.node.ID] = ident
	s.registered = true
	s.agentVersion = d.AgentVersion
	s.osStr = d.OS

	// Build the reconciliation list: every link whose other side is online
	// and registered contributes a full PeerSpec.
	var expected []proto.PeerSpec
	for _, l := range links {
		if h.links[l.ID] == nil {
			h.links[l.ID] = &linkRT{}
		}
		other := l.Other(s.node.ID)
		os_, ok := h.sessions[other]
		w, wok := h.lastWG[other]
		if !ok || os_ == nil || !os_.registered || !wok {
			continue
		}
		spec, err := h.peerSpecLocked(l, other, w)
		if err != nil {
			continue
		}
		expected = append(expected, spec)
		// register_ack delivery is implicit ACK for this side: a lost ack
		// tears down the session and the agent re-registers anyway.
		rt := h.links[l.ID]
		if peerSide(l, s.node.ID) == "a" {
			rt.ackA = true
		} else {
			rt.ackB = true
		}
		// Push this node's fresh ephemeral material to the other side.
		h.sendPeerSpecLocked(os_, l, proto.TypePeerUpdate, s.node.ID, ident)
	}
	h.mu.Unlock()

	ack, err := proto.NewEnvelope(proto.TypeRegisterAck, env.ID, proto.RegisterAckData{
		NodeID:        s.node.ID,
		OverlayIP:     s.node.OverlayIP + "/32",
		PeersExpected: expected,
	})
	if err != nil {
		return
	}
	s.send(ack)
	h.Store.TouchNode(s.node.ID, time.Now().Unix())
	h.Log.Info("registered", "node", s.node.ID, "wg_port", d.WGPort, "agent", d.AgentVersion)
}

func (h *Hub) handleHeartbeat(s *session, env *proto.Envelope) {
	var d proto.HeartbeatData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return
	}
	now := time.Now().Unix()
	h.mu.Lock()
	s.lastHB = now
	s.hbWG = d.WG
	// Update link runtime from the WG peer table: handshake timestamps and
	// byte counters (differentiated into rates).
	links, _ := h.Store.LinksOfNode(s.node.ID)
	for _, w := range d.WG {
		for _, l := range links {
			if l.Other(s.node.ID) != w.PeerNodeID {
				continue
			}
			rt := h.links[l.ID]
			if rt == nil {
				rt = &linkRT{}
				h.links[l.ID] = rt
			}
			if w.LastHandshakeTS > rt.lastHS {
				rt.lastHS = w.LastHandshakeTS
			}
			if rt.prevTS > 0 && now > rt.prevTS && w.RxBytes >= rt.prevRx && w.TxBytes >= rt.prevTx {
				dt := float64(now - rt.prevTS)
				rt.rxRate = float64(w.RxBytes-rt.prevRx) / dt
				rt.txRate = float64(w.TxBytes-rt.prevTx) / dt
			}
			rt.prevRx, rt.prevTx, rt.prevTS = w.RxBytes, w.TxBytes, now
		}
	}
	h.mu.Unlock()

	h.Metrics.Ingest(s.node.ID, d.TS, d.Sys)
	h.Store.TouchNode(s.node.ID, now)
	h.publish("heartbeat", map[string]any{"node_id": s.node.ID, "sys": d.Sys, "wg": d.WG})
}

func (h *Hub) handleAck(s *session, env *proto.Envelope) {
	var d proto.AckData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return
	}
	h.mu.Lock()
	ref, ok := s.pendingAcks[env.ID]
	delete(s.pendingAcks, env.ID)
	var l *Link
	if ok && d.OK {
		if rt := h.links[ref.linkID]; rt != nil {
			if ref.side == "a" {
				rt.ackA = true
			} else {
				rt.ackB = true
			}
		}
		l, _ = h.Store.GetLink(ref.linkID)
	}
	h.mu.Unlock()
	if !d.OK {
		h.Log.Warn("agent push failed", "node", s.node.ID, "err", d.Err)
	}
	if l != nil {
		h.publish("link_status", map[string]any{"link_id": l.ID, "status": h.LinkStatus(l)})
	}
}
