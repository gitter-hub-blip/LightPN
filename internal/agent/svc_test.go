package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// sealCmd replays the browser: derive the key from the password + the enc
// envelope's KDF params, then AES-256-GCM(JSON{action,alias,ts}).
func sealCmd(t *testing.T, dir, password, action, alias string, ts int64) proto.SvcActionData {
	t.Helper()
	vk, err := loadViewKey(dir)
	if err != nil || vk == nil {
		t.Fatalf("loadViewKey: %v", err)
	}
	salt, _ := base64.StdEncoding.DecodeString(vk.Salt)
	key := argon2.IDKey([]byte(password), salt, vk.Time, vk.MemKiB, vk.Par, 32)
	plain, _ := json.Marshal(svcCmd{Action: action, Alias: alias, TS: ts})
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, plain, nil)
	return proto.SvcActionData{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}
}

// fakeSvc is a platform-independent in-memory SvcManager for tests. The real
// NewSvcManager() is systemd-backed on Linux, so using it here would try to
// drive units that don't exist on a CI runner; these tests only exercise the
// command auth / alias / replay logic, not systemd itself.
type fakeSvc struct{ active map[string]bool }

func newFakeSvc() *fakeSvc { return &fakeSvc{active: map[string]bool{}} }

func (f *fakeSvc) Exists(string) bool { return true }
func (f *fakeSvc) Status(unit string) (string, string) {
	if f.active[unit] {
		return "active", "enabled"
	}
	return "inactive", "disabled"
}
func (f *fakeSvc) Do(action, unit string) error {
	if !svcActions[action] {
		return errTestBadAction
	}
	f.active[unit] = action != "stop"
	return nil
}

var errTestBadAction = errors.New("bad action")

func svcTestAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	if err := SetViewPassword(dir, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := AddSvc(dir, "ssrust", "shadowsocks-rust.service"); err != nil {
		t.Fatal(err)
	}
	a := &Agent{ID: &Identity{Dir: dir}, Log: slog.New(slog.DiscardHandler), Svc: newFakeSvc()}
	return a, dir
}

// TestSvcActionHappyPath: a correctly sealed command runs and flips state.
func TestSvcActionHappyPath(t *testing.T) {
	a, dir := svcTestAgent(t)
	now := int64(1_000_000)
	res := a.handleSvcAction(sealCmd(t, dir, "pw", "start", "ssrust", now), now)
	if !res.OK {
		t.Fatalf("expected OK, got err %q", res.Err)
	}
	var active string
	for _, s := range res.Services {
		if s.Alias == "ssrust" {
			active = s.Active
		}
	}
	if active != "active" {
		t.Fatalf("service not started: %q", active)
	}
}

// TestSvcActionWrongPassword: a command sealed with the wrong password must
// fail authentication — this is the whole point (a compromised hub knows the
// alias but not the password, so it can't forge commands).
func TestSvcActionWrongPassword(t *testing.T) {
	a, dir := svcTestAgent(t)
	now := int64(1_000_000)
	res := a.handleSvcAction(sealCmd(t, dir, "WRONG", "stop", "ssrust", now), now)
	if res.OK || res.Err == "" {
		t.Fatal("forged command accepted")
	}
}

// TestSvcActionReplay: replaying an identical sealed command is rejected.
func TestSvcActionReplay(t *testing.T) {
	a, dir := svcTestAgent(t)
	now := int64(1_000_000)
	cmd := sealCmd(t, dir, "pw", "restart", "ssrust", now)
	if res := a.handleSvcAction(cmd, now); !res.OK {
		t.Fatalf("first: %q", res.Err)
	}
	if res := a.handleSvcAction(cmd, now); res.OK {
		t.Fatal("replayed command accepted")
	}
}

// TestSvcActionExpired: a stale timestamp (outside the window) is rejected,
// so a captured-but-old command can't be used later.
func TestSvcActionExpired(t *testing.T) {
	a, dir := svcTestAgent(t)
	sealedTS := int64(1_000_000)
	cmd := sealCmd(t, dir, "pw", "stop", "ssrust", sealedTS)
	now := sealedTS + svcCmdWindow + 1
	if res := a.handleSvcAction(cmd, now); res.OK {
		t.Fatal("expired command accepted")
	}
}

// TestSvcActionUnknownAlias: a valid, authentic command for an alias that
// was never registered is refused (nothing to translate to a unit).
func TestSvcActionUnknownAlias(t *testing.T) {
	a, dir := svcTestAgent(t)
	now := int64(1_000_000)
	res := a.handleSvcAction(sealCmd(t, dir, "pw", "start", "ghost", now), now)
	if res.OK || res.Err == "" {
		t.Fatal("command for unregistered alias accepted")
	}
}

// TestSvcActionNoViewKey: without a view password the feature is inert — no
// key means no command can be authenticated.
func TestSvcActionNoViewKey(t *testing.T) {
	dir := t.TempDir()
	AddSvc(dir, "ssrust", "shadowsocks-rust.service")
	a := &Agent{ID: &Identity{Dir: dir}, Log: slog.New(slog.DiscardHandler), Svc: newFakeSvc()}
	// A command sealed under any key can't validate against an absent view key.
	res := a.handleSvcAction(proto.SvcActionData{Nonce: "AAAAAAAAAAAAAAAA", CT: "AAAA"}, 1_000_000)
	if res.OK {
		t.Fatal("service control worked without a view key")
	}
}

// TestSvcRegValidation: alias/unit patterns and duplicate rejection.
func TestSvcRegValidation(t *testing.T) {
	dir := t.TempDir()
	bad := []struct{ alias, unit string }{
		{"UPPER", "x.service"},        // alias not lowercase
		{"has space", "x.service"},    // alias space
		{"ok", "x"},                   // unit missing .service
		{"ok", "x.service; rm -rf /"}, // unit injection attempt
	}
	for _, c := range bad {
		if err := AddSvc(dir, c.alias, c.unit); err == nil {
			t.Errorf("AddSvc(%q,%q) accepted, want reject", c.alias, c.unit)
		}
	}
	if err := AddSvc(dir, "ok", "xray.service"); err != nil {
		t.Fatalf("valid AddSvc: %v", err)
	}
	if err := AddSvc(dir, "ok", "other.service"); err == nil {
		t.Error("duplicate alias accepted")
	}
	if err := AddSvc(dir, "ok2", "xray.service"); err == nil {
		t.Error("duplicate unit accepted")
	}
}

// TestSvcStatusRequiresViewKey: services are reported only on view-password
// nodes (no key → the whole feature stays dark to the hub).
func TestSvcStatusRequiresViewKey(t *testing.T) {
	dir := t.TempDir()
	AddSvc(dir, "ssrust", "shadowsocks-rust.service")
	a := &Agent{ID: &Identity{Dir: dir}, Log: slog.New(slog.DiscardHandler), Svc: newFakeSvc()}
	if got := a.collectSvcStatus(); got != nil {
		// collectSvcStatus itself doesn't gate on the key, but sealToolConf
		// only calls it on the encrypted path; assert the registry loads.
		if len(got) != 1 {
			t.Fatalf("unexpected status set: %+v", got)
		}
	}
	// The gate is in sealToolConf: no view key → plain result, no services.
	out := a.sealToolConf(proto.ConfResultData{})
	if len(out.Services) != 0 || out.Enc != nil {
		t.Fatal("services leaked without a view key")
	}
}
