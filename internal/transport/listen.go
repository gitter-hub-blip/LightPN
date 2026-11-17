// Package transport centralizes LightPN's TCP listener policy.
package transport

import (
	"context"
	"net"
)

// ListenTCP opens an ordinary TCP listener, even if GODEBUG enables MPTCP.
// This mitigates the demonstrated MPTCP exploitation path for
// CVE-2026-98432, but does not fix the underlying Linux kernel bug.
func ListenTCP(ctx context.Context, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(ctx, "tcp", address)
}
