package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// browserOpen replays exactly what the panel does with the password and the
// wire envelope: Argon2id(password, salt) → AES-256-GCM open → gunzip.
func browserOpen(t *testing.T, password string, enc *proto.ConfEnc) ([]byte, error) {
	t.Helper()
	salt, err := base64.StdEncoding.DecodeString(enc.Salt)
	if err != nil {
		t.Fatalf("salt b64: %v", err)
	}
	key := argon2.IDKey([]byte(password), salt, enc.Time, enc.MemKiB, enc.Par, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce, _ := base64.StdEncoding.DecodeString(enc.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(enc.CT)
	zipped, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return io.ReadAll(zr)
}

func testAgent(dir string) *Agent {
	return &Agent{ID: &Identity{Dir: dir}, Log: slog.New(slog.DiscardHandler)}
}

// TestViewKeyRoundTrip: set password → seal → decrypt the browser way; the
// recovered JSON must equal the plain conf_result.
func TestViewKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := SetViewPassword(dir, "correct horse"); err != nil {
		t.Fatalf("SetViewPassword: %v", err)
	}

	plain := proto.ConfResultData{
		WG: proto.ConfWG{Iface: "lightpn0", Pubkey: "pk", ListenPort: 51820},
		Files: []proto.ConfFile{
			{Tool: "shadowsocks-rust", Path: "/etc/shadowsocks-rust/config.json",
				Content: `{"server":"0.0.0.0","password":"topsecret"}`},
		},
	}
	sealed := testAgent(dir).sealToolConf(plain)
	if sealed.Enc == nil {
		t.Fatal("expected encrypted envelope, got plain")
	}
	// Alongside enc travels a masked preview: structure visible, secret
	// values dotted out. The real secret must not appear anywhere in it.
	if len(sealed.Files) != 1 || sealed.WG.Pubkey != "pk" {
		t.Fatalf("expected masked preview alongside enc, got %+v", sealed)
	}
	if got := sealed.Files[0].Content; strings.Contains(got, "topsecret") {
		t.Fatalf("secret leaked into preview: %s", got)
	} else if !strings.Contains(got, maskDots) {
		t.Fatalf("preview not masked: %s", got)
	}
	if sealed.Enc.KDF != "argon2id" || sealed.Enc.MemKiB != viewMemKiB || sealed.Enc.Time != viewTime {
		t.Fatalf("bad KDF params on the wire: %+v", sealed.Enc)
	}

	got, err := browserOpen(t, "correct horse", sealed.Enc)
	if err != nil {
		t.Fatalf("browser-side decrypt: %v", err)
	}
	want, _ := json.Marshal(plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch:\n got %s\nwant %s", got, want)
	}

	// Wrong password must fail GCM authentication, not yield garbage.
	if _, err := browserOpen(t, "wrong", sealed.Enc); err == nil {
		t.Fatal("wrong password decrypted successfully")
	}
}

// TestViewKeyAbsent: no view.key → conf_result passes through unencrypted
// (the pre-feature behavior).
func TestViewKeyAbsent(t *testing.T) {
	dir := t.TempDir()
	plain := proto.ConfResultData{WG: proto.ConfWG{Iface: "lightpn0"}}
	out := testAgent(dir).sealToolConf(plain)
	if out.Enc != nil {
		t.Fatal("encrypted without a view key")
	}
	if out.WG.Iface != "lightpn0" {
		t.Fatal("plain payload mangled")
	}
}

// TestViewKeyClear: clearing reverts to plaintext; clearing twice is a no-op.
func TestViewKeyClear(t *testing.T) {
	dir := t.TempDir()
	if err := SetViewPassword(dir, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := ClearViewPassword(dir); err != nil {
		t.Fatal(err)
	}
	if err := ClearViewPassword(dir); err != nil {
		t.Fatalf("second clear: %v", err)
	}
	if out := testAgent(dir).sealToolConf(proto.ConfResultData{}); out.Enc != nil {
		t.Fatal("still encrypting after clear")
	}
}

// TestViewKeyCorrupt: an unreadable/corrupt view.key must fail closed — an
// error entry, never the plaintext configs.
func TestViewKeyCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := SetViewPassword(dir, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := writeCorruptViewKey(dir); err != nil {
		t.Fatal(err)
	}
	plain := proto.ConfResultData{
		Files: []proto.ConfFile{{Tool: "xray", Content: "SECRET"}},
	}
	out := testAgent(dir).sealToolConf(plain)
	if out.Enc != nil {
		t.Fatal("sealed with a corrupt key?")
	}
	for _, f := range out.Files {
		if f.Content == "SECRET" {
			t.Fatal("fail-open: plaintext leaked with corrupt view.key")
		}
	}
	if len(out.Files) != 1 || out.Files[0].Err == "" {
		t.Fatalf("expected a single error entry, got %+v", out.Files)
	}
}

func writeCorruptViewKey(dir string) error {
	return os.WriteFile(viewKeyPath(dir), []byte("{not json"), 0o600)
}

// TestMaskSecrets: the Go port must mask what web/app.js MASK_RE masks —
// JSON and YAML forms, CRLF preserved, empty values left empty (index
// alignment with the panel depends on identical match behavior).
func TestMaskSecrets(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"json",
			`{"server":"1.2.3.4","password":"hunter2","method":"aes"}`,
			`{"server":"1.2.3.4","password":"` + maskDots + `","method":"aes"}`},
		{"json empty value stays empty",
			`{"password":""}`,
			`{"password":""}`},
		{"yaml",
			"server: 1.2.3.4\npassword: hunter2\nport: 443\n",
			"server: 1.2.3.4\npassword: " + maskDots + "\nport: 443\n"},
		{"yaml crlf preserved",
			"password: hunter2\r\nport: 443\r\n",
			"password: " + maskDots + "\r\nport: 443\r\n"},
		{"yaml list item",
			"- private_key: abc123\n",
			"- private_key: " + maskDots + "\n"},
		{"uuid json",
			`{"id": "8a7b-uuid-value"}`,
			`{"id": "` + maskDots + `"}`},
		{"no secrets untouched",
			"listen: 0.0.0.0\nmode: tcp\n",
			"listen: 0.0.0.0\nmode: tcp\n"},
	}
	for _, c := range cases {
		if got := maskSecrets(c.in); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
