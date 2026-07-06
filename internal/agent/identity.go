package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is the agent's only persisted state ("who I am", never "who I
// have connected to" — design invariant 2).
type Identity struct {
	Dir string

	NodeID        string `json:"node_id"`
	ControlAddr   string `json:"control_addr"`
	OverlayIP     string `json:"overlay_ip"`   // with /32
	OverlayCIDR   string `json:"overlay_cidr"` // e.g. 100.100.0.0/24
	CAFingerprint string `json:"ca_fingerprint"`
}

func identityPaths(dir string) (key, cert, ca, state string) {
	return filepath.Join(dir, "identity.key"),
		filepath.Join(dir, "identity.crt"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "state.json")
}

// LoadIdentity reads a previously enrolled identity.
func LoadIdentity(dir string) (*Identity, error) {
	_, _, _, statePath := identityPaths(dir)
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	id := &Identity{Dir: dir}
	if err := json.Unmarshal(data, id); err != nil {
		return nil, err
	}
	return id, nil
}

// Save writes identity material to dir with tight permissions.
func (id *Identity) Save(keyPEM, certPEM, caPEM string) error {
	if err := os.MkdirAll(id.Dir, 0o700); err != nil {
		return err
	}
	keyPath, certPath, caPath, statePath := identityPaths(id.Dir)
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(caPath, []byte(caPEM), 0o644); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, data, 0o600)
}

// UpdateCert replaces the client certificate (rotate_cert).
func (id *Identity) UpdateCert(certPEM string) error {
	_, certPath, _, _ := identityPaths(id.Dir)
	return os.WriteFile(certPath, []byte(certPEM), 0o644)
}

// Destroy removes all identity files (kick).
func (id *Identity) Destroy() error {
	return os.RemoveAll(id.Dir)
}

// TLSConfig builds the mTLS client config with the CA pinned (TOFU: the CA
// recorded at enrollment is the only accepted root, and its fingerprint is
// re-checked on every connection).
func (id *Identity) TLSConfig() (*tls.Config, error) {
	keyPath, certPath, caPath, _ := identityPaths(id.Dir)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, errors.New("invalid CA PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(caCert.Raw)
	if id.CAFingerprint != "" && hex.EncodeToString(sum[:]) != id.CAFingerprint {
		return nil, errors.New("CA fingerprint mismatch — possible tampering")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "lightpn-hub",
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CAFingerprintOf computes the fingerprint to record at enrollment.
func CAFingerprintOf(caPEM string) (string, error) {
	block, _ := pem.Decode([]byte(caPEM))
	if block == nil {
		return "", errors.New("invalid CA PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
