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
	"regexp"
	"strings"

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

// maskRE mirrors MASK_RE in web/app.js — the two MUST stay in sync so the
// agent-side preview masks exactly what the panel would. JSON ("key": "v")
// and YAML (key: v) forms; the trailing (\r?) group preserves CRLF files.
var maskRE = regexp.MustCompile(`(?im)("(?:privatekey|private_key|password|passwd|secret|secret_key|uuid|psk|token|auth|pass|id)"\s*:\s*")([^"]*)(")|^([ \t-]*(?:private[_-]?key|password|passwd|secret(?:[_-]key)?|uuid|psk|token|auth(?:[_-]str)?|pass)\s*:[ \t]*)([^#\r\n]+?)(\r?)$`)

const maskDots = "••••••••"

// maskSecrets replaces secret values in a config text with fixed-width dots
// (no length leak). Regex-based: keys the pattern misses stay in the clear,
// the same limitation the panel-side masking always had.
func maskSecrets(text string) string {
	var b strings.Builder
	last := 0
	for _, m := range maskRE.FindAllStringSubmatchIndex(text, -1) {
		b.WriteString(text[last:m[0]])
		if m[2] >= 0 { // JSON: prefix, value, closing quote
			b.WriteString(text[m[2]:m[3]])
			if m[5] > m[4] {
				b.WriteString(maskDots)
			}
			b.WriteString(text[m[6]:m[7]])
		} else { // YAML: prefix, value, optional \r
			b.WriteString(text[m[8]:m[9]])
			b.WriteString(maskDots)
			b.WriteString(text[m[12]:m[13]])
		}
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// sealToolConf wraps a collected conf_result for the wire. With a view
// password configured it sends a masked plaintext preview (structure visible,
// secret values dotted out) alongside the full result encrypted in Enc: the
// panel renders the preview immediately and asks for the password only when
// a masked value is clicked. Deliberate trade-off vs sealing everything:
// hub/CDN see config structure (addresses, ports) but not secrets. On a
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
		return res // no password configured — plain, as before
	}
	plain, err := json.Marshal(res)
	if err == nil {
		var enc *proto.ConfEnc
		if enc, err = vk.seal(plain); err == nil {
			preview := proto.ConfResultData{WG: res.WG, Enc: enc}
			preview.Files = make([]proto.ConfFile, len(res.Files))
			for i, f := range res.Files {
				f.Content = maskSecrets(f.Content)
				preview.Files[i] = f
			}
			return preview
		}
	}
	a.Log.Error("conf encryption failed", "err", err)
	return proto.ConfResultData{Files: []proto.ConfFile{{
		Tool: "lightpn", Path: viewKeyPath(a.ID.Dir),
		Err: fmt.Sprintf("conf encryption failed: %v", err),
	}}}
}
