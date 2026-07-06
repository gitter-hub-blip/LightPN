package agent

import (
	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// WGManager abstracts kernel WireGuard operations. The real implementation
// (wg_linux.go) drives the kernel module via wgctrl; other platforms get a
// compile-only stub so the agent can be developed anywhere.
type WGManager interface {
	// Init creates the device, generates an ephemeral key pair (design
	// invariant 2: never persisted) and assigns the overlay address.
	// Returns the base64 public key and the actual listen port.
	Init(overlayIP, overlayCIDR string, listenPort int) (pubkey string, port int, err error)
	// Reconcile makes the kernel peer set exactly match specs (§5.3).
	Reconcile(specs []proto.PeerSpec) error
	AddPeer(spec proto.PeerSpec) error
	// UpdatePeer replaces a peer identified by link: same semantics as
	// peer_update (§5.5) — old key for the same node is removed.
	UpdatePeer(spec proto.PeerSpec) error
	RemovePeer(pubkeyB64 string) error
	// Status reports current peers with node-ID mapping for heartbeats.
	Status() ([]proto.WGPeerStatus, error)
	// Rotate generates a fresh key pair on the existing device, dropping
	// all peers (they refer to sessions keyed on the old key anyway).
	Rotate() (pubkey string, err error)
	// Teardown removes the device entirely (kick).
	Teardown() error
}
