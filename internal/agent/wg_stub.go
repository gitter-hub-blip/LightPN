//go:build !linux

package agent

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// stubWG is a compile-only in-memory fake for non-Linux development. It
// tracks peer state faithfully but touches no kernel.
type stubWG struct {
	mu        sync.Mutex
	pub       string
	port      int
	peerNodes map[string]string
	nodeKeys  map[string]string
}

// NewWGManager returns the development stub on non-Linux platforms.
func NewWGManager() (WGManager, error) {
	return &stubWG{peerNodes: map[string]string{}, nodeKeys: map[string]string{}}, nil
}

func fakeKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (w *stubWG) Init(overlayIP, overlayCIDR string, listenPort int) (string, int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pub = fakeKey()
	w.port = listenPort
	w.peerNodes = map[string]string{}
	w.nodeKeys = map[string]string{}
	return w.pub, listenPort, nil
}

func (w *stubWG) Reconcile(specs []proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.peerNodes = map[string]string{}
	w.nodeKeys = map[string]string{}
	for _, s := range specs {
		w.peerNodes[s.WGPubkey] = s.PeerNodeID
		w.nodeKeys[s.PeerNodeID] = s.WGPubkey
	}
	return nil
}

func (w *stubWG) AddPeer(spec proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.peerNodes[spec.WGPubkey] = spec.PeerNodeID
	w.nodeKeys[spec.PeerNodeID] = spec.WGPubkey
	return nil
}

func (w *stubWG) UpdatePeer(spec proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if old, ok := w.nodeKeys[spec.PeerNodeID]; ok {
		delete(w.peerNodes, old)
	}
	w.peerNodes[spec.WGPubkey] = spec.PeerNodeID
	w.nodeKeys[spec.PeerNodeID] = spec.WGPubkey
	return nil
}

func (w *stubWG) RemovePeer(pubkeyB64 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if nodeID, ok := w.peerNodes[pubkeyB64]; ok {
		delete(w.peerNodes, pubkeyB64)
		delete(w.nodeKeys, nodeID)
	}
	return nil
}

func (w *stubWG) Status() ([]proto.WGPeerStatus, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []proto.WGPeerStatus{}
	for pub, nodeID := range w.peerNodes {
		_ = pub
		out = append(out, proto.WGPeerStatus{PeerNodeID: nodeID})
	}
	return out, nil
}

func (w *stubWG) Rotate() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pub = fakeKey()
	w.peerNodes = map[string]string{}
	w.nodeKeys = map[string]string{}
	return w.pub, nil
}

func (w *stubWG) Teardown() error { return nil }
