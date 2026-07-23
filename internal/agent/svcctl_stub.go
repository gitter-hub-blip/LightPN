//go:build !linux

package agent

import (
	"fmt"
	"sync"
)

// stubSvc is an in-memory fake for non-Linux development: every unit
// "exists", starts stopped, and actions flip its state faithfully.
type stubSvc struct {
	mu     sync.Mutex
	active map[string]bool
}

// NewSvcManager returns the platform service manager.
func NewSvcManager() SvcManager { return &stubSvc{active: map[string]bool{}} }

func (s *stubSvc) Exists(string) bool { return true }

func (s *stubSvc) Status(unit string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[unit] {
		return "active", "enabled"
	}
	return "inactive", "disabled"
}

func (s *stubSvc) Do(action, unit string) error {
	if !svcActions[action] {
		return fmt.Errorf("action %q not allowed", action)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[unit] = action != "stop"
	return nil
}
