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
