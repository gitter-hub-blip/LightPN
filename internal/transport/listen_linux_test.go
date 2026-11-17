package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestListenTCPDisablesMPTCP(t *testing.T) {
	for _, setting := range []string{"0", "1", "2", "3"} {
		t.Run("multipathtcp="+setting, func(t *testing.T) {
			t.Setenv("GODEBUG", "multipathtcp="+setting)
			ln, err := ListenTCP(context.Background(), "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			tcpLn := ln.(*net.TCPListener)
			raw, err := tcpLn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var protocol int
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				protocol, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			}); err != nil {
				t.Fatal(err)
			}
			if sockErr != nil {
				t.Fatal(sockErr)
			}
			if protocol != unix.IPPROTO_TCP {
				t.Fatalf("listener protocol = %d, want ordinary TCP (%d)", protocol, unix.IPPROTO_TCP)
			}

			// An MPTCP-capable client must still connect via TCP fallback.
			d := net.Dialer{Timeout: time.Second}
			d.SetMultipathTCP(true)
			client, err := d.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := tcpLn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			server, err := tcpLn.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			mptcp, err := server.MultipathTCP()
			if err != nil {
				t.Fatal(err)
			}
			if mptcp {
				t.Fatal("accepted connection unexpectedly uses MPTCP")
			}
		})
	}
}
