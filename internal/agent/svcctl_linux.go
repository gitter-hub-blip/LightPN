//go:build linux

package agent

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// systemdSvc drives systemctl with fixed argv — no shell is ever involved,
// and unit names reach here only via the local registry (svcreg.go).
type systemdSvc struct{}

// NewSvcManager returns the platform service manager.
func NewSvcManager() SvcManager { return systemdSvc{} }

func (systemdSvc) Exists(unit string) bool {
	// LoadState=loaded for known units; "not-found" otherwise.
	out, err := exec.Command("systemctl", "show", "-P", "LoadState", "--", unit).Output()
	return err == nil && strings.TrimSpace(string(out)) == "loaded"
}

func (systemdSvc) Status(unit string) (active, enabled string) {
	// is-active / is-enabled exit non-zero for inactive/disabled but still
	// print the state word — read stdout regardless of the exit code.
	out, _ := exec.Command("systemctl", "is-active", "--", unit).Output()
	active = strings.TrimSpace(string(out))
	out, _ = exec.Command("systemctl", "is-enabled", "--", unit).Output()
	enabled = strings.TrimSpace(string(out))
	if active == "" {
		active = "unknown"
	}
	if enabled == "" {
		enabled = "unknown"
	}
	return active, enabled
}

func (systemdSvc) Do(action, unit string) error {
	if !svcActions[action] {
		return fmt.Errorf("action %q not allowed", action)
	}
	cmd := exec.Command("systemctl", action, "--", unit)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("systemctl %s %s: %w", action, unit, err)
		}
		return nil
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return fmt.Errorf("systemctl %s %s: timed out", action, unit)
	}
}
