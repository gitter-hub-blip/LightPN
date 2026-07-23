package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// View-password key derivation parameters (Argon2id). The derivation runs
// once on the agent at password-set time and once in the operator's browser
// per viewing session; conf_get itself never pays the Argon2 cost.
const (
	viewKDF     = "argon2id"
	viewMemKiB  = 64 * 1024 // 64 MiB
	viewTime    = 3
	viewPar     = 1
	viewSaltLen = 16
	viewKeyLen  = 32 // AES-256
)

// viewKey is the persisted conf-view encryption state. Storing the derived
// key (not the password) means conf_get encrypts with a plain file read; the
// key protects the transport and the hub, not the local disk — the plaintext
// config files it guards live on the same disk with the same root-only
// access, so this is no weakening (cf. the WG-private-key invariant, which
// is about material that must never exist outside the agent at all).
type viewKey struct {
	KDF    string `json:"kdf"`
	MemKiB uint32 `json:"m_kib"`
	Time   uint32 `json:"t"`
	Par    uint8  `json:"p"`
	Salt   string `json:"salt"` // base64 std
	Key    string `json:"key"`  // base64 std, derived key — file is 0600
}

func viewKeyPath(dir string) string { return filepath.Join(dir, "view.key") }

// SetViewPassword derives the view key from password and persists it.
// Called by the set-view-pass CLI (deploy-time), not by the daemon.
func SetViewPassword(dir, password string) error {
	if password == "" {
		return errors.New("empty password")
	}
	salt := make([]byte, viewSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), salt, viewTime, viewMemKiB, viewPar, viewKeyLen)
	vk := viewKey{
		KDF: viewKDF, MemKiB: viewMemKiB, Time: viewTime, Par: viewPar,
		Salt: base64.StdEncoding.EncodeToString(salt),
		Key:  base64.StdEncoding.EncodeToString(key),
	}
	data, err := json.MarshalIndent(vk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(viewKeyPath(dir), data, 0o600)
}

// HasViewKey reports whether a view password is configured (CLI hints).
func HasViewKey(dir string) bool {
	_, err := os.Stat(viewKeyPath(dir))
	return err == nil
}

// ClearViewPassword removes the view key; conf_get replies revert to plain.
func ClearViewPassword(dir string) error {
	err := os.Remove(viewKeyPath(dir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// loadViewKey reads the persisted view key. (nil, nil) when no password is
// configured. Read on every conf_get so a password set or cleared while the
// daemon runs takes effect without a restart.
func loadViewKey(dir string) (*viewKey, error) {
	data, err := os.ReadFile(viewKeyPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	vk := &viewKey{}
	if err := json.Unmarshal(data, vk); err != nil {
		return nil, err
	}
	if vk.KDF != viewKDF || vk.Salt == "" || vk.Key == "" {
		return nil, errors.New("malformed view.key")
	}
	return vk, nil
}

// seal encrypts the plain conf_result JSON: gzip, then AES-256-GCM under the
// stored key with a fresh nonce. The gzip step keeps base64(ct) under the
// 1 MiB frame cap even at confTotalCap.
func (vk *viewKey) seal(plainJSON []byte) (*proto.ConfEnc, error) {
	key, err := base64.StdEncoding.DecodeString(vk.Key)
	if err != nil || len(key) != viewKeyLen {
		return nil, errors.New("malformed view.key key material")
	}
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	if _, err := zw.Write(plainJSON); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, zbuf.Bytes(), nil)
	return &proto.ConfEnc{
		KDF: vk.KDF, MemKiB: vk.MemKiB, Time: vk.Time, Par: vk.Par,
		Salt:  vk.Salt,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// sealToolConf wraps a collected conf_result for the wire. Config contents
// are viewable ONLY with a view password: without one the reply is just the
// WG summary plus NoKey (the panel shows how to set a password). With one,
// the outer payload carries file METADATA (tool/alias, path, size, err — so
// the panel can draw the service bars before unlock) and the service list;
// every byte of file content travels solely inside Enc and is decrypted in
// the operator's browser. hub/CDN never see contents or structure. On a
// broken view.key it fails closed — an error entry instead of plaintext.
func (a *Agent) sealToolConf(res proto.ConfResultData) proto.ConfResultData {
	vk, err := loadViewKey(a.ID.Dir)
	if err != nil {
		a.Log.Error("view key unreadable, refusing plaintext conf", "err", err)
		return proto.ConfResultData{Files: []proto.ConfFile{{
			Tool: "lightpn", Path: viewKeyPath(a.ID.Dir),
			Err: fmt.Sprintf("view key unreadable: %v", err),
		}}}
	}
	if vk == nil {
		return proto.ConfResultData{WG: res.WG, NoKey: true}
	}
	// Registered services ride along on view-password nodes only. They go
	// into BOTH the sealed payload and the outer metadata: the panel swaps
	// in the decrypted payload wholesale after unlock, so anything missing
	// from it would vanish from the page at that moment.
	res.Services = a.collectSvcStatus()
	plain, err := json.Marshal(res)
	if err == nil {
		var enc *proto.ConfEnc
		if enc, err = vk.seal(plain); err == nil {
			outer := proto.ConfResultData{WG: res.WG, Services: res.Services, Enc: enc}
			outer.Files = make([]proto.ConfFile, len(res.Files))
			for i, f := range res.Files {
				f.Content = "" // contents live in Enc only
				f.Truncated = false
				outer.Files[i] = f
			}
			return outer
		}
	}
	a.Log.Error("conf encryption failed", "err", err)
	return proto.ConfResultData{Files: []proto.ConfFile{{
		Tool: "lightpn", Path: viewKeyPath(a.ID.Dir),
		Err: fmt.Sprintf("conf encryption failed: %v", err),
	}}}
}
