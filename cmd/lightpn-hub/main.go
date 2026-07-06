// lightpn-hub is the LightPN central node: enrollment CA, IPAM, link
// matchmaking, metrics collection and the embedded admin panel.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gitter-hub-blip/lightpn/internal/hub"
	"github.com/gitter-hub-blip/lightpn/internal/pki"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "admin" && os.Args[2] == "set-password" {
		setPassword(os.Args[3:])
		return
	}
	serve(os.Args[1:])
}

func loadConfig(args []string) hub.Config {
	fs := flag.NewFlagSet("lightpn-hub", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file (optional)")
	dataDir := fs.String("data-dir", "", "data directory (SQLite + CA)")
	controlAddr := fs.String("control-addr", "", "control channel listen address")
	apiAddr := fs.String("api-addr", "", "admin API listen address (keep on loopback)")
	publicAddr := fs.String("public-addr", "", "public control address given to agents (host:port)")
	overlayCIDR := fs.String("overlay-cidr", "", "overlay network CIDR")
	fs.Parse(args)

	cfg, err := hub.LoadConfig(*configPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *controlAddr != "" {
		cfg.ControlAddr = *controlAddr
	}
	if *apiAddr != "" {
		cfg.APIAddr = *apiAddr
	}
	if *publicAddr != "" {
		cfg.PublicAddr = *publicAddr
	}
	if *overlayCIDR != "" {
		cfg.OverlayCIDR = *overlayCIDR
	}
	return cfg
}

func openStore(cfg hub.Config) *hub.Store {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fatal("data dir: %v", err)
	}
	store, err := hub.OpenStore(filepath.Join(cfg.DataDir, "hub.db"))
	if err != nil {
		fatal("open store: %v", err)
	}
	return store
}

func serve(args []string) {
	cfg := loadConfig(args)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	store := openStore(cfg)
	defer store.Close()

	if ok, err := store.HasAdmin(); err == nil && !ok {
		log.Warn("no admin account yet — run: lightpn-hub admin set-password")
	}

	ca, err := pki.LoadOrCreate(cfg.DataDir)
	if err != nil {
		fatal("CA: %v", err)
	}
	log.Info("CA ready", "fingerprint", ca.Fingerprint()[:16])

	h, err := hub.New(cfg, store, ca, log)
	if err != nil {
		fatal("hub init: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Info("shutting down")
		close(stop)
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- h.ServeControl(stop) }()
	go func() { errCh <- h.ServeAPI(stop) }()
	go h.Run(stop)

	if err := <-errCh; err != nil {
		fatal("%v", err)
	}
	<-stop
}

func setPassword(args []string) {
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	configPath := fs.String("config", "", "JSON config file (optional)")
	dataDir := fs.String("data-dir", "", "data directory")
	username := fs.String("username", "admin", "admin username")
	fs.Parse(args)

	cfg, err := hub.LoadConfig(*configPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	store := openStore(cfg)
	defer store.Close()

	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "New password for %q: ", *username)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("read password: %v", err)
		}
		password = string(raw)
	} else {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			password = strings.TrimSpace(sc.Text())
		}
	}
	if len(password) < 8 {
		fatal("password must be at least 8 characters")
	}
	hash, err := hub.HashPassword(password)
	if err != nil {
		fatal("hash: %v", err)
	}
	if err := store.SetAdmin(*username, hash); err != nil {
		fatal("save admin: %v", err)
	}
	fmt.Printf("admin %q password set\n", *username)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lightpn-hub: "+format+"\n", args...)
	os.Exit(1)
}
