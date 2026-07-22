package agent

import (
	"errors"
	"log/slog"
	"os"
	"reflect"
	"testing"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

type fakeExitWG struct {
	applied []proto.ExitWGSpec
	pub     string
	err     error
}

func (f *fakeExitWG) Apply(s proto.ExitWGSpec) (string, error) {
	f.applied = append(f.applied, s)
	return f.pub, f.err
}
func (f *fakeExitWG) Teardown() error { return nil }

// TestApplyExitWGPersistence: a successful apply persists the spec (so a
// reboot without the hub restores the operator's VPN) and reports the
// manager's pubkey; a failed apply reports the error and must NOT overwrite
// the last known-good spec.
func TestApplyExitWGPersistence(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	few := &fakeExitWG{pub: "SRVPUB"}
	a := &Agent{ID: &Identity{Dir: dir}, ExitWG: few, Log: log}

	spec := proto.ExitWGSpec{
		Enabled: true, Port: 51821, CIDR: "10.99.0.1/24",
		Peers: []proto.ExitWGPeer{{Pubkey: "CPUB", IP: "10.99.0.2/32"}},
	}
	st := a.applyExitWG(spec)
	if !st.Enabled || st.Pubkey != "SRVPUB" || st.Err != "" {
		t.Fatalf("bad state report: %+v", st)
	}
	loaded, err := loadExitWGSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, spec) {
		t.Fatalf("persisted spec = %+v, want %+v", loaded, spec)
	}

	// Failing apply: error reported, persisted spec untouched.
	few.err = errors.New("boom")
	st = a.applyExitWG(proto.ExitWGSpec{Enabled: false, Port: 1, CIDR: "10.99.0.1/24"})
	if st.Err == "" {
		t.Fatal("expected error in state report")
	}
	loaded, err = loadExitWGSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Enabled || loaded.Port != 51821 {
		t.Fatalf("failed apply overwrote persisted spec: %+v", loaded)
	}
}
