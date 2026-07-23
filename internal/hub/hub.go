// Package hub implements the LightPN hub: node admission, IPAM, link
// matchmaking and observation.
package hub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/pki"
	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// Hub is the central orchestrator. All runtime (non-persisted) state lives
// here: live sessions, link runtime status, last-known WG material, the
// revocation list and the metrics rings.
type Hub struct {
	Cfg     Config
	Store   *Store
	CA      *pki.CA
	Metrics *Metrics
	Log     *slog.Logger

	mu           sync.Mutex
	controlBound string              // actual control listener address
	sessions     map[string]*session // nodeID -> live session
	links    map[string]*linkRT  // linkID -> runtime state
	lastWG   map[string]wgIdent  // nodeID -> last known WG material
	revoked  map[string]bool     // cert serial -> revoked
	gcDone   map[string]bool     // nodeID -> peers already GC'd from others
	confWait map[string]confWaiter // conf_get envelope ID -> waiting API call

	subsMu sync.Mutex
	subs   map[chan Event]bool

	enrollMu    sync.Mutex
	enrollTries map[string][]time.Time // enroll rate limit, per source IP
}

// confWaiter is a pending panel request for a node's tool configuration:
// the API handler blocks on ch until the matching conf_result arrives.
// nodeID pins the reply to the session that was asked.
type confWaiter struct {
	nodeID string
	ch     chan json.RawMessage
}

// wgIdent is a node's last-registered ephemeral WG material plus the
// endpoint IP observed from its control connection (invariant 5).
type wgIdent struct {
	pubkey    string
	port      int
	ip        string
	socksPort int // exit SOCKS5 port bound to the node's overlay IP (0 = off)
}

func (w wgIdent) endpoint() string { return fmt.Sprintf("%s:%d", w.ip, w.port) }

// linkRT tracks the per-link runtime needed for the pending/active/degraded
// state machine and rate display.
type linkRT struct {
	ackA, ackB bool // current pushes ACKed by each side
	lastHS     int64
	rxRate     float64
	txRate     float64
	prevRx     uint64
	prevTx     uint64
	prevTS     int64
}

// Event is a panel-facing WS event.
type Event struct {
	Ev   string `json:"ev"`
	Data any    `json:"data"`
}

// New assembles a Hub from an opened store and CA.
func New(cfg Config, store *Store, ca *pki.CA, log *slog.Logger) (*Hub, error) {
	revoked, err := store.RevokedSerials()
	if err != nil {
		return nil, err
	}
	return &Hub{
		Cfg:      cfg,
		Store:    store,
		CA:       ca,
		Metrics:  NewMetrics(),
		Log:      log,
		sessions: map[string]*session{},
		links:    map[string]*linkRT{},
		lastWG:   map[string]wgIdent{},
		revoked:  revoked,
		gcDone:   map[string]bool{},
		confWait: map[string]confWaiter{},
		subs:     map[chan Event]bool{},
	}, nil
}

// Run starts background loops (offline peer GC). Blocks until stop is closed.
func (h *Hub) Run(stop <-chan struct{}) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			h.gcOfflinePeers()
		}
	}
}

// ---- event bus ----

// Subscribe returns a channel receiving panel events; call the returned
// cancel func to unsubscribe.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.subsMu.Lock()
	h.subs[ch] = true
	h.subsMu.Unlock()
	return ch, func() {
		h.subsMu.Lock()
		delete(h.subs, ch)
		h.subsMu.Unlock()
	}
}

func (h *Hub) publish(ev string, data any) {
	h.subsMu.Lock()
	defer h.subsMu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- Event{Ev: ev, Data: data}:
		default: // slow panel session: drop, WS layer will resync on demand
		}
	}
}

// ---- status ----

// NodeStatus returns online / stale / offline for a node.
func (h *Hub) NodeStatus(id string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nodeStatusLocked(id)
}

func (h *Hub) nodeStatusLocked(id string) string {
	s := h.sessions[id]
	if s == nil {
		return "offline"
	}
	if time.Now().Unix()-s.lastHB > int64(h.Cfg.DeadAfterS) {
		return "stale"
	}
	return "online"
}

// LinkStatus computes the link state machine value.
// pending: at least one side offline or not yet ACKed
// active: both ACKed and a handshake seen within 180s
// degraded: both ACKed but no recent handshake
func (h *Hub) LinkStatus(l *Link) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	rt := h.links[l.ID]
	aOn := h.sessions[l.A] != nil && h.sessions[l.A].registered
	bOn := h.sessions[l.B] != nil && h.sessions[l.B].registered
	if rt == nil || !aOn || !bOn || !rt.ackA || !rt.ackB {
		return "pending"
	}
	if time.Now().Unix()-rt.lastHS < 180 {
		return "active"
	}
	return "degraded"
}

// LinkRuntime returns (lastHandshake, rxRate, txRate) for display.
func (h *Hub) LinkRuntime(id string) (int64, float64, float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rt := h.links[id]
	if rt == nil {
		return 0, 0, 0
	}
	return rt.lastHS, rt.rxRate, rt.txRate
}

// SessionInfo exposes per-node liveness details for the API layer.
type SessionInfo struct {
	Endpoint     string
	AgentVersion string
	LastHB       int64
	WGPeers      []proto.WGPeerStatus
	ExitCapable  bool // agent advertised an exit SOCKS port
}

func (h *Hub) Session(id string) (SessionInfo, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[id]
	if s == nil {
		return SessionInfo{}, false
	}
	info := SessionInfo{AgentVersion: s.agentVersion, LastHB: s.lastHB, WGPeers: s.hbWG}
	if w, ok := h.lastWG[id]; ok {
		info.Endpoint = w.endpoint()
		info.ExitCapable = w.socksPort > 0
	}
	return info, true
}

// ---- matchmaking ----

// pushPeers pushes the pair to both ends of a link if online; used on link
// creation. Offline sides are naturally covered later by register reconcile.
func (h *Hub) pushLink(l *Link) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.links[l.ID] == nil {
		h.links[l.ID] = &linkRT{}
	}
	h.pushPairLocked(l, proto.TypePeerAdd)
}

// pushPairLocked sends typ (peer_add or peer_update) to both sides of l for
// each side that is online and registered. Caller holds h.mu.
func (h *Hub) pushPairLocked(l *Link, typ string) {
	sa, sb := h.sessions[l.A], h.sessions[l.B]
	wa, waOK := h.lastWG[l.A]
	wb, wbOK := h.lastWG[l.B]
	if sa == nil || sb == nil || !sa.registered || !sb.registered || !waOK || !wbOK {
		return // pending; register reconcile will complete it
	}
	rt := h.links[l.ID]
	rt.ackA, rt.ackB = false, false
	h.sendPeerSpecLocked(sa, l, typ, l.B, wb)
	h.sendPeerSpecLocked(sb, l, typ, l.A, wa)
}

func (h *Hub) sendPeerSpecLocked(s *session, l *Link, typ, peerID string, w wgIdent) {
	spec, err := h.peerSpecLocked(l, peerID, w)
	if err != nil {
		h.Log.Error("build peer spec", "err", err)
		return
	}
	id := NewULID()
	s.pendingAcks[id] = ackRef{linkID: l.ID, side: peerSide(l, s.node.ID)}
	env, err := proto.NewEnvelope(typ, id, spec)
	if err != nil {
		return
	}
	s.send(env)
}

func (h *Hub) peerSpecLocked(l *Link, peerID string, w wgIdent) (proto.PeerSpec, error) {
	peer, err := h.Store.GetNode(peerID)
	if err != nil {
		return proto.PeerSpec{}, err
	}
	spec := proto.PeerSpec{
		LinkID:     l.ID,
		PeerNodeID: peerID,
		PeerName:   peer.Name,
		WGPubkey:   w.pubkey,
		Endpoint:   w.endpoint(),
		AllowedIPs: []string{peer.OverlayIP + "/32"},
		KeepaliveS: h.Cfg.KeepaliveS,
	}
	// The receiver of this spec is the other end of the link. If the link
	// designates `peerID` as the exit node and the peer actually runs an
	// exit SOCKS, tell the receiver to egress through it.
	if l.ExitNode == peerID && peerID != l.Other(peerID) && w.socksPort > 0 {
		spec.Exit = true
		spec.ExitAddr = fmt.Sprintf("%s:%d", peer.OverlayIP, w.socksPort)
	}
	return spec, nil
}

// peerSide returns which ack flag nodeID owns on link l ("a" or "b").
func peerSide(l *Link, nodeID string) string {
	if l.A == nodeID {
		return "a"
	}
	return "b"
}

// removeLinkFromPeers pushes peer_remove to both online ends of l.
func (h *Hub) removeLinkFromPeers(l *Link) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeSideLocked(l, l.A, l.B)
	h.removeSideLocked(l, l.B, l.A)
	delete(h.links, l.ID)
}

// removeSideLocked tells `to` to drop `peerID`'s WG peer.
func (h *Hub) removeSideLocked(l *Link, to, peerID string) {
	s := h.sessions[to]
	w, ok := h.lastWG[peerID]
	if s == nil || !ok {
		return
	}
	env, err := proto.NewEnvelope(proto.TypePeerRemove, NewULID(), proto.PeerRemoveData{
		LinkID: l.ID, WGPubkey: w.pubkey,
	})
	if err != nil {
		return
	}
	s.send(env)
}

// gcOfflinePeers implements §5.6: after a node has been offline longer than
// peer_gc_after, its peers are removed from the other ends.
func (h *Hub) gcOfflinePeers() {
	nodes, err := h.Store.ListNodes()
	if err != nil {
		h.Log.Error("gc: list nodes", "err", err)
		return
	}
	now := time.Now().Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range nodes {
		if h.sessions[n.ID] != nil || h.gcDone[n.ID] {
			continue
		}
		if n.LastSeen == 0 || now-n.LastSeen < int64(h.Cfg.PeerGCAfterS) {
			continue
		}
		links, err := h.Store.LinksOfNode(n.ID)
		if err != nil {
			continue
		}
		for _, l := range links {
			h.removeSideLocked(l, l.Other(n.ID), n.ID)
		}
		h.gcDone[n.ID] = true
		h.Log.Info("gc: removed offline node from peers", "node", n.ID)
	}
}

// ---- admin-triggered operations ----

// CreateLink stores and (if possible) immediately pushes a link.
func (h *Hub) CreateLink(a, b string) (*Link, error) {
	l, err := h.Store.CreateLink(a, b, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	h.pushLink(l)
	h.publish("link_status", map[string]any{"link_id": l.ID, "status": h.LinkStatus(l)})
	return l, nil
}

// SetLinkExit designates (exitNode = A or B) or clears (exitNode = "") the
// internet egress for a link, then re-pushes the pair so the non-exit side
// updates its exit SOCKS upstream (peer_update carries Exit/ExitAddr).
func (h *Hub) SetLinkExit(id, exitNode string) (*Link, error) {
	l, err := h.Store.SetLinkExit(id, exitNode)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	if h.links[l.ID] == nil {
		h.links[l.ID] = &linkRT{}
	}
	h.pushPairLocked(l, proto.TypePeerUpdate)
	h.mu.Unlock()
	h.publish("link_status", map[string]any{"link_id": l.ID, "status": h.LinkStatus(l)})
	return l, nil
}

// DeleteLink removes a link and withdraws it from both ends.
func (h *Hub) DeleteLink(id string) error {
	l, err := h.Store.GetLink(id)
	if err != nil {
		return err
	}
	if err := h.Store.DeleteLink(id); err != nil {
		return err
	}
	h.removeLinkFromPeers(l)
	h.publish("link_status", map[string]any{"link_id": id, "status": "deleted"})
	return nil
}

// DeleteNode performs the §6.2 cascade: delete links → peer_remove to other
// ends → kick target → revoke cert → IP into cooldown.
func (h *Hub) DeleteNode(id string) error {
	node, links, err := h.Store.DeleteNode(id, time.Now().Unix())
	if err != nil {
		return err
	}
	h.mu.Lock()
	for _, l := range links {
		h.removeSideLocked(l, l.Other(id), id)
		delete(h.links, l.ID)
	}
	h.revoked[node.CertSerial] = true
	s := h.sessions[id]
	h.mu.Unlock()

	if s != nil {
		env, _ := proto.NewEnvelope(proto.TypeKick, NewULID(), proto.KickData{Reason: "removed by admin"})
		s.send(env)
		// give the frame a moment to flush, then drop the session
		time.AfterFunc(2*time.Second, s.close)
	}
	h.Metrics.Drop(id)
	h.mu.Lock()
	delete(h.lastWG, id)
	delete(h.gcDone, id)
	h.mu.Unlock()
	h.publish("node_status", map[string]any{"node_id": id, "status": "deleted"})
	return nil
}

// RotateWG asks a node to regenerate its WG key (it will re-register).
func (h *Hub) RotateWG(id string) error {
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		return fmt.Errorf("node %s is offline", id)
	}
	env, err := proto.NewEnvelope(proto.TypeRotateWG, NewULID(), struct{}{})
	if err != nil {
		return err
	}
	s.send(env)
	return nil
}

// ErrConfTimeout reports that an agent did not answer conf_get in time.
var ErrConfTimeout = fmt.Errorf("agent did not answer in time")

// requestReply pushes an envelope to a node and waits for the reply frame
// carrying the same envelope ID (conf_get→conf_result, svc_action→
// svc_result). Nothing is cached or persisted: every call is a fresh round
// trip to the edge (hub minimal-persistence invariant).
func (h *Hub) requestReply(id, typ string, payload any, timeout time.Duration) (json.RawMessage, error) {
	h.mu.Lock()
	s := h.sessions[id]
	if s == nil {
		h.mu.Unlock()
		return nil, fmt.Errorf("node %s is offline", id)
	}
	reqID := NewULID()
	ch := make(chan json.RawMessage, 1)
	h.confWait[reqID] = confWaiter{nodeID: id, ch: ch}
	h.mu.Unlock()

	cleanup := func() {
		h.mu.Lock()
		delete(h.confWait, reqID)
		h.mu.Unlock()
	}
	env, err := proto.NewEnvelope(typ, reqID, payload)
	if err != nil {
		cleanup()
		return nil, err
	}
	s.send(env)
	select {
	case data := <-ch:
		cleanup()
		return data, nil
	case <-time.After(timeout):
		cleanup()
		return nil, ErrConfTimeout
	}
}

// RequestToolConf pushes conf_get to a node and waits for its conf_result
// (panel-triggered, §6.2).
func (h *Hub) RequestToolConf(id string, timeout time.Duration) (json.RawMessage, error) {
	return h.requestReply(id, proto.TypeConfGet, struct{}{}, timeout)
}

// RequestSvcAction relays a browser-sealed service command and waits for
// the agent's svc_result. The hub never sees inside d.CT — it cannot forge,
// alter, or usefully replay a command (agent-side GCM + nonce cache).
func (h *Hub) RequestSvcAction(id string, d proto.SvcActionData, timeout time.Duration) (json.RawMessage, error) {
	return h.requestReply(id, proto.TypeSvcAction, d, timeout)
}

// handleConfResult delivers an agent's conf_result or svc_result to the
// waiting API call. The waiter is keyed by the request's envelope ID and
// pinned to the node it was sent to, so another session cannot spoof a
// reply.
func (h *Hub) handleConfResult(s *session, env *proto.Envelope) {
	h.mu.Lock()
	w, ok := h.confWait[env.ID]
	if ok && w.nodeID == s.node.ID {
		delete(h.confWait, env.ID)
	} else {
		ok = false
	}
	h.mu.Unlock()
	if ok {
		w.ch <- env.Data
	}
}

// ControlBoundAddr reports the control listener's actual address once
// ServeControl has bound it (useful with port 0 in tests).
func (h *Hub) ControlBoundAddr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.controlBound
}

// isRevoked checks the in-memory revocation list.
func (h *Hub) isRevoked(serial string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.revoked[serial]
}
