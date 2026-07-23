package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCollectToolConf: existing candidate files are read with metadata,
// missing ones are skipped, oversized ones are truncated at the cap, and
// the WG summary carries the agent's runtime identity (never a private key).
func TestCollectToolConf(t *testing.T) {
	dir := t.TempDir()
	xrayPath := filepath.Join(dir, "xray.json")
	bigPath := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(xrayPath, []byte(`{"inbounds":[{"protocol":"vless"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bigPath, []byte(strings.Repeat("x", confFileCap+100)), 0600); err != nil {
		t.Fatal(err)
	}

	orig := toolConfCandidates
	defer func() { toolConfCandidates = orig }()
	toolConfCandidates = []struct{ tool, path string }{
		{"xray", xrayPath},
		{"sing-box", filepath.Join(dir, "does-not-exist.json")},
		{"hysteria", bigPath},
	}

	a := &Agent{WG: &fakeWG{}, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	a.wgPub, a.wgListenPort = "TESTPUB", 51999

	res := a.collectToolConf()
	if res.WG.Pubkey != "TESTPUB" || res.WG.ListenPort != 51999 || res.WG.Iface == "" {
		t.Fatalf("bad WG summary: %+v", res.WG)
	}
	if len(res.Files) != 2 {
		t.Fatalf("want 2 files (missing path skipped), got %d: %+v", len(res.Files), res.Files)
	}
	xr := res.Files[0]
	if xr.Tool != "xray" || !strings.Contains(xr.Content, "vless") || xr.Truncated || xr.Size == 0 || xr.ModTime == 0 {
		t.Fatalf("bad xray entry: %+v", xr)
	}
	big := res.Files[1]
	if !big.Truncated || len(big.Content) != confFileCap {
		t.Fatalf("big file not truncated at cap: truncated=%v len=%d", big.Truncated, len(big.Content))
	}
}

// TestCollectToolConfRegistered: svc-registry entries with a conf path are
// read like builtin candidates (tool = alias); a registered-but-unreadable
// path yields an Err entry instead of a silent skip — the operator promised
// that path, so its failure must be visible. A registered duplicate of a
// builtin path that was already served is not emitted twice.
func TestCollectToolConfRegistered(t *testing.T) {
	dir := t.TempDir()
	caddyfile := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte(":443 {\n  forward_proxy {\n    basic_auth u p\n  }\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	orig := toolConfCandidates
	defer func() { toolConfCandidates = orig }()
	toolConfCandidates = []struct{ tool, path string }{
		{"caddy", caddyfile}, // also registered below — must not duplicate
	}

	// saveSvcReg directly: AddSvc's Linux-absolute-path check would reject
	// the Windows-style t.TempDir() path (validation is TestSvcRegValidation's
	// job; here we test collection).
	idDir := t.TempDir()
	if err := saveSvcReg(idDir, []SvcEntry{
		{Alias: "naive", Unit: "caddy.service", Conf: caddyfile}, // dup of builtin
		{Alias: "gone", Unit: "gone.service", Conf: "/nonexistent/config.json"},
		{Alias: "silent", Unit: "silent.service"}, // no conf → no file entry
	}); err != nil {
		t.Fatal(err)
	}

	a := &Agent{ID: &Identity{Dir: idDir}, WG: &fakeWG{}, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	res := a.collectToolConf()
	if len(res.Files) != 2 {
		t.Fatalf("want 2 files (builtin + missing registered), got %d: %+v", len(res.Files), res.Files)
	}
	if f := res.Files[0]; f.Tool != "caddy" || !strings.Contains(f.Content, "basic_auth") {
		t.Fatalf("bad builtin entry: %+v", f)
	}
	if f := res.Files[1]; f.Tool != "gone" || f.Err == "" || f.Content != "" {
		t.Fatalf("missing registered path must surface an Err entry: %+v", f)
	}
}
