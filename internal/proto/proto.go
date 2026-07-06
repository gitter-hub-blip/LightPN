// Package proto defines the LightPN control-channel wire protocol:
// a 4-byte big-endian length prefix followed by a JSON envelope.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Version is the current protocol version carried in every envelope.
const Version = 1

// MaxFrame is the maximum size of a single frame (1 MiB).
const MaxFrame = 1 << 20

// Message types (see AGENT.md appendix A).
const (
	TypeEnroll      = "enroll"
	TypeEnrollAck   = "enroll_ack"
	TypeRegister    = "register"
	TypeRegisterAck = "register_ack"
	TypeHeartbeat   = "heartbeat"
	TypePeerAdd     = "peer_add"
	TypePeerRemove  = "peer_remove"
	TypePeerUpdate  = "peer_update"
	TypeAck         = "ack"
	TypeKick        = "kick"
	TypeRotateWG    = "rotate_wg"
	TypeRotateCert  = "rotate_cert"
	TypeError       = "error"
)

// Error codes.
const (
	ErrTokenExpired       = "TOKEN_EXPIRED"
	ErrTokenUsed          = "TOKEN_USED"
	ErrAuthFailed         = "AUTH_FAILED"
	ErrCertRevoked        = "CERT_REVOKED"
	ErrVersionUnsupported = "VERSION_UNSUPPORTED"
	ErrIPAMExhausted      = "IPAM_EXHAUSTED"
	ErrUnknownType        = "UNKNOWN_TYPE"
	ErrInternal           = "INTERNAL"
)

// Envelope is the shared message envelope.
type Envelope struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

// NewEnvelope marshals data into an envelope.
func NewEnvelope(typ, id string, data any) (*Envelope, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &Envelope{V: Version, Type: typ, ID: id, Data: raw}, nil
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, env *Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > MaxFrame {
		return fmt.Errorf("frame too large: %d bytes", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadFrame reads one length-prefixed frame.
func ReadFrame(r io.Reader) (*Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// ---- payloads ----

type EnrollData struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	CSRPEM   string `json:"csr_pem"`
}

type EnrollAckData struct {
	NodeID      string `json:"node_id"`
	CertPEM     string `json:"cert_pem"`
	CAPEM       string `json:"ca_pem"`
	OverlayIP   string `json:"overlay_ip"`   // e.g. 100.100.0.7/32
	OverlayCIDR string `json:"overlay_cidr"` // e.g. 100.100.0.0/24
	ControlAddr string `json:"control_addr"`
}

type RegisterData struct {
	WGPubkey     string `json:"wg_pubkey"`
	WGPort       int    `json:"wg_port"`
	AgentVersion string `json:"agent_version"`
	OS           string `json:"os"`
}

type RegisterAckData struct {
	NodeID        string     `json:"node_id"`
	OverlayIP     string     `json:"overlay_ip"`
	PeersExpected []PeerSpec `json:"peers_expected"`
}

// PeerSpec is the full peer description pushed in peer_add/peer_update
// and in register_ack reconciliation lists.
type PeerSpec struct {
	LinkID     string   `json:"link_id"`
	PeerNodeID string   `json:"peer_node_id"`
	PeerName   string   `json:"peer_name"`
	WGPubkey   string   `json:"wg_pubkey"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	KeepaliveS int      `json:"keepalive_s"`
}

type PeerRemoveData struct {
	LinkID   string `json:"link_id"`
	WGPubkey string `json:"wg_pubkey"`
}

type SysMetrics struct {
	CPUPct    float64 `json:"cpu_pct"`
	Load1     float64 `json:"load1"`
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskTotal uint64  `json:"disk_total"`
	NetRx     uint64  `json:"net_rx_bytes"`
	NetTx     uint64  `json:"net_tx_bytes"`
	UptimeS   uint64  `json:"uptime_s"`
}

type WGPeerStatus struct {
	PeerNodeID      string `json:"peer_node_id"`
	LastHandshakeTS int64  `json:"last_handshake_ts"`
	RxBytes         uint64 `json:"rx_bytes"`
	TxBytes         uint64 `json:"tx_bytes"`
	Endpoint        string `json:"endpoint"`
}

type HeartbeatData struct {
	TS  int64          `json:"ts"`
	Sys SysMetrics     `json:"sys"`
	WG  []WGPeerStatus `json:"wg"`
}

type AckData struct {
	OK  bool   `json:"ok"`
	Err string `json:"err"`
}

type KickData struct {
	Reason string `json:"reason"`
}

type RotateCertData struct {
	CertPEM string `json:"cert_pem"`
}

type ErrorData struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}
