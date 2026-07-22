//go:build !linux

package agent

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"sync"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// stubExitWG mirrors the linux manager's key persistence so the protocol
// flow (stable pubkey across applies/restarts) is testable anywhere.
type stubExitWG struct {
	mu      sync.Mutex
	dataDir string
	enabled bool
}

// NewExitWGManager returns the development stub on non-Linux platforms.
func NewExitWGManager(dataDir string) ExitWGManager {
	return &stubExitWG{dataDir: dataDir}
}

// serverPubkey loads or creates the fake persistent key; only the "pubkey"
// (derived deterministically from the stored secret) is ever exposed.
func (w *stubExitWG) serverPubkey(create bool) (string, error) {
	keyPath, _ := exitWGPaths(w.dataDir)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		if !create {
			return "", nil
		}
		b := make([]byte, 32)
		rand.Read(b)
		data = []byte(base64.StdEncoding.EncodeToString(b) + "\n")
		if err := os.WriteFile(keyPath, data, 0o600); err != nil {
			return "", err
		}
	}
	// Fake derivation: reverse the secret bytes. Stable, obviously not real.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return "", err
	}
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (w *stubExitWG) Apply(spec proto.ExitWGSpec) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = spec.Enabled
	return w.serverPubkey(spec.Enabled)
}

func (w *stubExitWG) Teardown() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = false
	return nil
}
