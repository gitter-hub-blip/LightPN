package agent

import "github.com/gitter-hub-blip/lightpn/internal/proto"

// SvcManager abstracts systemd service control. The real implementation
// (svcctl_linux.go) shells out to systemctl with a fixed argv — never
// through a shell, and only with unit names from the local registry. Other
// platforms get an in-memory stub for development.
type SvcManager interface {
	// Exists reports whether the unit is known to systemd (offered by the
	// svc-add CLI to validate registrations).
	Exists(unit string) bool
	// Status returns the unit's ActiveState and UnitFileState.
	Status(unit string) (active, enabled string)
	// Do runs action ∈ {start, stop, restart} on the unit.
	Do(action, unit string) error
}

// svcActions is the complete set of allowed actions — a sealed command with
// anything else is rejected before touching systemctl.
var svcActions = map[string]bool{"start": true, "stop": true, "restart": true}

// collectSvcStatus resolves the registry to wire-form statuses. Unit names
// stay local; only aliases and states leave the box.
func (a *Agent) collectSvcStatus() []proto.SvcStatus {
	if a.Svc == nil {
		return nil
	}
	reg, err := LoadSvcReg(a.ID.Dir)
	if err != nil || len(reg) == 0 {
		return nil
	}
	out := make([]proto.SvcStatus, 0, len(reg))
	for _, e := range reg {
		active, enabled := a.Svc.Status(e.Unit)
		out = append(out, proto.SvcStatus{Alias: e.Alias, Active: active, Enabled: enabled})
	}
	return out
}
