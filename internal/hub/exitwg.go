package hub

// Direct-connect WG ("直连 WG"): a hub-managed WG server on an edge node for
// the operator's own devices (full-tunnel internet exit), independent of the
// mesh. The hub persists desired state (an accepted exception to invariant
// 4) and pushes it via exitwg_set / register_ack; the agent answers with
// exitwg_status carrying its persistent server pubkey.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// Defaults for a node whose direct WG has never been configured.
const (
	DefaultExitWGPort = 51821
	DefaultExitWGCIDR = "10.99.0.1/24"
)

// ExitWGConfig is a node's stored direct-WG configuration.
type ExitWGConfig struct {
	NodeID  string
	Enabled bool
	Port    int
	CIDR    string
	Pubkey  string // agent-reported persistent server pubkey ("" until first enable)
}

// ExitWGPeer is one stored client device.
type ExitWGPeer struct {
	ID        string
	NodeID    string
	Name      string
	Pubkey    string
	IP        string // with /32
	CreatedAt int64
}

// ---- store ----

// GetExitWG returns the node's config, or defaults if never configured.
func (s *Store) GetExitWG(nodeID string) (*ExitWGConfig, error) {
	c := &ExitWGConfig{NodeID: nodeID, Port: DefaultExitWGPort, CIDR: DefaultExitWGCIDR}
	var enabled int
	err := s.db.QueryRow(`SELECT enabled,port,cidr,pubkey FROM exitwg WHERE node_id=?`, nodeID).
		Scan(&enabled, &c.Port, &c.CIDR, &c.Pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled = enabled != 0
	return c, nil
}

// SetExitWG upserts the enable flag and port, keeping cidr and pubkey.
func (s *Store) SetExitWG(nodeID string, enabled bool, port int) (*ExitWGConfig, error) {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO exitwg (node_id,enabled,port,cidr) VALUES (?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET enabled=excluded.enabled, port=excluded.port`,
		nodeID, en, port, DefaultExitWGCIDR)
	if err != nil {
		return nil, err
	}
	return s.GetExitWG(nodeID)
}

// SetExitWGPubkey records the agent-reported server pubkey.
func (s *Store) SetExitWGPubkey(nodeID, pubkey string) error {
	_, err := s.db.Exec(`INSERT INTO exitwg (node_id,enabled,port,cidr,pubkey) VALUES (?,0,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET pubkey=excluded.pubkey`,
		nodeID, DefaultExitWGPort, DefaultExitWGCIDR, pubkey)
	return err
}

func (s *Store) ListExitWGPeers(nodeID string) ([]*ExitWGPeer, error) {
	rows, err := s.db.Query(`SELECT id,node_id,name,pubkey,ip,created_at FROM exitwg_peers WHERE node_id=? ORDER BY created_at`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ExitWGPeer{}
	for rows.Next() {
		var p ExitWGPeer
		if err := rows.Scan(&p.ID, &p.NodeID, &p.Name, &p.Pubkey, &p.IP, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// AddExitWGPeer stores a client device, assigning the lowest free address in
// the node's direct-WG subnet (server address and network/broadcast skipped).
func (s *Store) AddExitWGPeer(nodeID, name, pubkey string, now int64) (*ExitWGPeer, error) {
	cfg, err := s.GetExitWG(nodeID)
	if err != nil {
		return nil, err
	}
	serverPrefix, err := netip.ParsePrefix(cfg.CIDR)
	if err != nil {
		return nil, err
	}
	peers, err := s.ListExitWGPeers(nodeID)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{serverPrefix.Addr().String(): true}
	for _, p := range peers {
		if p.Pubkey == pubkey {
			return nil, errors.New("this device pubkey is already added")
		}
		pfx, err := netip.ParsePrefix(p.IP)
		if err == nil {
			used[pfx.Addr().String()] = true
		}
	}
	subnet := serverPrefix.Masked()
	network := subnet.Addr()
	broadcast := lastAddr(subnet)
	var ip string
	for a := network.Next(); subnet.Contains(a) && a != broadcast; a = a.Next() {
		if !used[a.String()] {
			ip = a.String() + "/32"
			break
		}
	}
	if ip == "" {
		return nil, errors.New("direct WG subnet exhausted")
	}
	p := &ExitWGPeer{ID: NewULID(), NodeID: nodeID, Name: name, Pubkey: pubkey, IP: ip, CreatedAt: now}
	_, err = s.db.Exec(`INSERT INTO exitwg_peers (id,node_id,name,pubkey,ip,created_at) VALUES (?,?,?,?,?,?)`,
		p.ID, p.NodeID, p.Name, p.Pubkey, p.IP, p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) DeleteExitWGPeer(nodeID, peerID string) error {
	res, err := s.db.Exec(`DELETE FROM exitwg_peers WHERE id=? AND node_id=?`, peerID, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- hub ops ----

// ExitWGSpec assembles the authoritative desired state pushed to an agent.
// Always non-nil: a never-configured node gets a disabled spec so stale
// local state on the agent converges away.
func (h *Hub) ExitWGSpec(nodeID string) (*proto.ExitWGSpec, error) {
	cfg, err := h.Store.GetExitWG(nodeID)
	if err != nil {
		return nil, err
	}
	peers, err := h.Store.ListExitWGPeers(nodeID)
	if err != nil {
		return nil, err
	}
	spec := &proto.ExitWGSpec{Enabled: cfg.Enabled, Port: cfg.Port, CIDR: cfg.CIDR}
	for _, p := range peers {
		spec.Peers = append(spec.Peers, proto.ExitWGPeer{Pubkey: p.Pubkey, IP: p.IP})
	}
	return spec, nil
}

// PushExitWG sends the node's current desired state if it is online;
// offline nodes converge via register_ack when they return.
func (h *Hub) PushExitWG(nodeID string) error {
	spec, err := h.ExitWGSpec(nodeID)
	if err != nil {
		return err
	}
	h.mu.Lock()
	s := h.sessions[nodeID]
	h.mu.Unlock()
	if s == nil {
		return nil
	}
	env, err := proto.NewEnvelope(proto.TypeExitWGSet, NewULID(), spec)
	if err != nil {
		return err
	}
	s.send(env)
	return nil
}

// handleExitWGState stores the agent-reported server pubkey and fans the
// state out to panel sessions.
func (h *Hub) handleExitWGState(s *session, env *proto.Envelope) {
	var d proto.ExitWGStateData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return
	}
	if d.Pubkey != "" {
		if err := h.Store.SetExitWGPubkey(s.node.ID, d.Pubkey); err != nil {
			h.Log.Error("store exitwg pubkey", "node", s.node.ID, "err", err)
		}
	}
	if d.Err != "" {
		h.Log.Warn("agent exit WG error", "node", s.node.ID, "err", d.Err)
	}
	h.publish("exitwg_status", map[string]any{
		"node_id": s.node.ID, "enabled": d.Enabled, "pubkey": d.Pubkey, "err": d.Err,
	})
}

// ExitWGEndpointHost is the host part clients should dial: the node's
// public IP as observed on the control channel (invariant 5), known only
// while the node has registered this session.
func (h *Hub) ExitWGEndpointHost(nodeID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if w, ok := h.lastWG[nodeID]; ok {
		return w.ip
	}
	return ""
}
