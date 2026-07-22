package agent

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// ExitWGManager drives the direct-connect WG interface (lightpn1): a
// hub-managed WG server for the operator's own devices, separate from the
// mesh device. Unlike the mesh key, its server key is persisted so client
// device configs survive agent restarts.
type ExitWGManager interface {
	// Apply converges the device to spec (create/update/tear down) and
	// returns the persistent server public key ("" if none exists yet).
	Apply(spec proto.ExitWGSpec) (pubkey string, err error)
	// Teardown removes the device and any NAT rules (kick / shutdown).
	Teardown() error
}

// The direct-connect WG state is deliberately persisted (an accepted
// exception to the zero-connection-records invariant, which governs mesh
// peers): the operator's personal VPN must survive an agent restart even
// when the hub is unreachable. The hub remains the source of truth and
// overwrites this on every register.
func exitWGPaths(dir string) (keyPath, specPath string) {
	return filepath.Join(dir, "exitwg.key"), filepath.Join(dir, "exitwg.json")
}

func saveExitWGSpec(dir string, spec proto.ExitWGSpec) error {
	_, specPath := exitWGPaths(dir)
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(specPath, data, 0o600)
}

func loadExitWGSpec(dir string) (proto.ExitWGSpec, error) {
	_, specPath := exitWGPaths(dir)
	var spec proto.ExitWGSpec
	data, err := os.ReadFile(specPath)
	if err != nil {
		return spec, err
	}
	err = json.Unmarshal(data, &spec)
	return spec, err
}

// applyExitWG converges the device, persists the spec for hub-independent
// restarts, and returns the state report for the hub.
func (a *Agent) applyExitWG(spec proto.ExitWGSpec) proto.ExitWGStateData {
	st := proto.ExitWGStateData{Enabled: spec.Enabled, Port: spec.Port}
	pubkey, err := a.ExitWG.Apply(spec)
	st.Pubkey = pubkey
	if err != nil {
		st.Err = err.Error()
		a.Log.Error("exit WG apply", "enabled", spec.Enabled, "err", err)
		return st
	}
	if err := saveExitWGSpec(a.ID.Dir, spec); err != nil {
		a.Log.Warn("persist exit WG spec", "err", err)
	}
	a.Log.Info("exit WG applied", "enabled", spec.Enabled, "port", spec.Port, "peers", len(spec.Peers))
	return st
}
