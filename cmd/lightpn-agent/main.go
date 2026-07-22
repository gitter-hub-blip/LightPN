// lightpn-agent is the LightPN edge node daemon.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/agent"
)

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		enroll(os.Args[2:])
		return
	}
	run(os.Args[1:])
}

func enroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	hubAddr := fs.String("hub", "", "hub control address host:port (required)")
	token := fs.String("token", "", "one-time enrollment token (required)")
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	fs.Parse(args)
	if *hubAddr == "" || *token == "" {
		fatal("usage: lightpn-agent enroll --hub <ip>:7440 --token <token>")
	}
	if _, err := agent.LoadIdentity(*dataDir); err == nil {
		fatal("identity already exists in %s — this machine is already enrolled", *dataDir)
	}
	id, err := agent.Enroll(*hubAddr, *token, *dataDir)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("enrolled: node %s, overlay %s\nstart the agent with: lightpn-agent --data-dir %s\n",
		id.NodeID, id.OverlayIP, *dataDir)
}

func run(args []string) {
	fs := flag.NewFlagSet("lightpn-agent", flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "identity directory")
	wgPort := fs.Int("wg-port", 51820, "WireGuard listen port")
	heartbeat := fs.Int("heartbeat-s", 15, "heartbeat period seconds")
	socksPort := fs.Int("socks-port", 0, "enable exit SOCKS5 on this port (bound to the overlay IP); 0 = disabled")
	socksListen := fs.String("socks-listen", "", "override exit SOCKS5 bind address (default <overlay-ip>:<socks-port>)")
	exitVia := fs.String("exit-via", "", "pin egress through this overlay SOCKS address, e.g. 100.100.0.9:1080 (overrides hub-driven exit; for testing)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	id, err := agent.LoadIdentity(*dataDir)
	if err != nil {
		fatal("no identity in %s — enroll first: lightpn-agent enroll --hub <ip>:7440 --token <token>", *dataDir)
	}
	wg, err := agent.NewWGManager()
	if err != nil {
		fatal("%v", err)
	}

	a := &agent.Agent{
		ID:              id,
		WG:              wg,
		ExitWG:          agent.NewExitWGManager(*dataDir),
		Log:             log,
		WGPort:          *wgPort,
		HeartbeatPeriod: time.Duration(*heartbeat) * time.Second,
	}

	// Exit SOCKS5: enable it if a port is set, a bind is overridden, or a
	// manual upstream is pinned.
	if *socksPort > 0 || *socksListen != "" || *exitVia != "" {
		ec, err := agent.NewExitController(log, *exitVia)
		if err != nil {
			fatal("exit controller: %v", err)
		}
		a.Exit = ec
		bind := *socksListen
		port := *socksPort
		if bind == "" {
			overlayIP := strings.SplitN(id.OverlayIP, "/", 2)[0]
			if port == 0 {
				port = 1080
			}
			bind = net.JoinHostPort(overlayIP, strconv.Itoa(port))
		} else if port == 0 {
			if _, p, err := net.SplitHostPort(bind); err == nil {
				port, _ = strconv.Atoi(p)
			}
		}
		a.SocksListen = bind
		// Only advertise the port to the hub (so other nodes may exit via
		// us) when the listener is overlay-reachable, i.e. not loopback.
		if host, _, err := net.SplitHostPort(bind); err == nil && !isLoopback(host) {
			a.SocksPort = port
		}
	}

	err = a.Run()
	if errors.Is(err, agent.ErrKicked) {
		log.Warn("removed by hub administrator; identity destroyed")
		os.Exit(0)
	}
	fatal("%v", err)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lightpn-agent: "+format+"\n", args...)
	os.Exit(1)
}
