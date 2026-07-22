//go:build linux

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const exitDeviceName = "lightpn1"

// linuxExitWG manages the direct-connect WG device plus the forwarding/NAT
// plumbing that makes it a full-tunnel internet exit.
type linuxExitWG struct {
	mu      sync.Mutex
	dataDir string
	client  *wgctrl.Client
	// applied NAT parameters, kept for exact rule removal on disable
	natCIDR string
	natIfc  string
}

// NewExitWGManager returns the kernel implementation. The wgctrl client is
// opened lazily in Apply so a missing module only fails when the feature is
// actually enabled.
func NewExitWGManager(dataDir string) ExitWGManager {
	return &linuxExitWG{dataDir: dataDir}
}

func (w *linuxExitWG) ensureClient() error {
	if w.client != nil {
		return nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl: %w", err)
	}
	w.client = c
	return nil
}

// serverKey loads the persistent server key, generating it on first use.
// Persistence is the point: the operator's device configs pin this pubkey.
func (w *linuxExitWG) serverKey(create bool) (wgtypes.Key, bool, error) {
	keyPath, _ := exitWGPaths(w.dataDir)
	if data, err := os.ReadFile(keyPath); err == nil {
		k, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
		return k, true, err
	}
	if !create {
		return wgtypes.Key{}, false, nil
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, false, err
	}
	if err := os.WriteFile(keyPath, []byte(k.String()+"\n"), 0o600); err != nil {
		return wgtypes.Key{}, false, err
	}
	return k, true, nil
}

func (w *linuxExitWG) Apply(spec proto.ExitWGSpec) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !spec.Enabled {
		// A disable arriving in a fresh process (agent restarted since the
		// rules were added) has no in-memory NAT record; reconstruct it from
		// the spec so removeNATLocked can still clean up.
		if w.natCIDR == "" && spec.CIDR != "" {
			if prefix, err := netip.ParsePrefix(spec.CIDR); err == nil {
				if ifc, err := defaultRouteIfc(); err == nil {
					w.natCIDR, w.natIfc = prefix.Masked().String(), ifc
				}
			}
		}
		if err := w.teardownLocked(); err != nil {
			return "", err
		}
		// Report the persistent pubkey (if any) so the panel keeps showing it.
		if k, ok, err := w.serverKey(false); err == nil && ok {
			return k.PublicKey().String(), nil
		}
		return "", nil
	}

	if err := w.ensureClient(); err != nil {
		return "", err
	}
	key, _, err := w.serverKey(true)
	if err != nil {
		return "", fmt.Errorf("server key: %w", err)
	}
	prefix, err := netip.ParsePrefix(spec.CIDR)
	if err != nil {
		return "", fmt.Errorf("cidr %q: %w", spec.CIDR, err)
	}

	if _, err := net.InterfaceByName(exitDeviceName); err != nil {
		if err := ipCmd("link", "add", exitDeviceName, "type", "wireguard"); err != nil {
			return "", err
		}
	}
	if err := ipCmd("addr", "replace", spec.CIDR, "dev", exitDeviceName); err != nil {
		return "", err
	}

	var peers []wgtypes.PeerConfig
	for _, p := range spec.Peers {
		pk, err := wgtypes.ParseKey(p.Pubkey)
		if err != nil {
			return "", fmt.Errorf("client pubkey %q: %w", p.Pubkey, err)
		}
		_, ipnet, err := net.ParseCIDR(p.IP)
		if err != nil {
			return "", fmt.Errorf("client ip %q: %w", p.IP, err)
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         pk,
			AllowedIPs:        []net.IPNet{*ipnet},
			ReplaceAllowedIPs: true,
		})
	}
	err = w.client.ConfigureDevice(exitDeviceName, wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &spec.Port,
		ReplacePeers: true, // hub state is authoritative: removed devices drop off
		Peers:        peers,
	})
	if err != nil {
		return "", fmt.Errorf("configure %s: %w", exitDeviceName, err)
	}
	if err := ipCmd("link", "set", "up", "dev", exitDeviceName); err != nil {
		return "", err
	}
	if err := w.applyNATLocked(prefix.Masked().String()); err != nil {
		return "", err
	}
	return key.PublicKey().String(), nil
}

// applyNATLocked turns the box into an internet exit for the direct-WG
// subnet: ip_forward on, MASQUERADE out the default-route interface, and
// FORWARD accepts for hosts whose default policy is DROP. Rules are added
// idempotently (-C before -A) and recorded for exact removal.
func (w *linuxExitWG) applyNATLocked(subnet string) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	ifc, err := defaultRouteIfc()
	if err != nil {
		return err
	}
	// Re-applied with different parameters (subnet/ifc changed): drop the
	// old rules first so they don't accumulate.
	if (w.natCIDR != "" && w.natCIDR != subnet) || (w.natIfc != "" && w.natIfc != ifc) {
		w.removeNATLocked()
	}
	for _, r := range natRules(subnet, ifc) {
		if exec.Command("iptables", r.cmd("-C")...).Run() == nil {
			continue // already present
		}
		if out, err := exec.Command("iptables", r.cmd("-A")...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %v: %s", strings.Join(r.cmd("-A"), " "), err, strings.TrimSpace(string(out)))
		}
	}
	w.natCIDR, w.natIfc = subnet, ifc
	return nil
}

type natRule struct {
	table string // "" = filter
	chain string
	args  []string
}

// cmd builds the iptables argv for op ∈ -C (check) / -A (append) / -D (delete).
func (r natRule) cmd(op string) []string {
	var out []string
	if r.table != "" {
		out = append(out, "-t", r.table)
	}
	return append(append(out, op, r.chain), r.args...)
}

func natRules(subnet, ifc string) []natRule {
	return []natRule{
		{"nat", "POSTROUTING", []string{"-s", subnet, "-o", ifc, "-j", "MASQUERADE"}},
		{"", "FORWARD", []string{"-i", exitDeviceName, "-j", "ACCEPT"}},
		{"", "FORWARD", []string{"-o", exitDeviceName, "-j", "ACCEPT"}},
	}
}

func (w *linuxExitWG) removeNATLocked() {
	if w.natCIDR == "" {
		return
	}
	for _, r := range natRules(w.natCIDR, w.natIfc) {
		exec.Command("iptables", r.cmd("-D")...).Run() // best-effort cleanup
	}
	w.natCIDR, w.natIfc = "", ""
}

// defaultRouteIfc finds the interface carrying the default route.
func defaultRouteIfc() (string, error) {
	out, err := exec.Command("ip", "-o", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route show default: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route interface found")
}

func (w *linuxExitWG) Teardown() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.teardownLocked()
}

func (w *linuxExitWG) teardownLocked() error {
	w.removeNATLocked()
	if _, err := net.InterfaceByName(exitDeviceName); err != nil {
		return nil
	}
	return ipCmd("link", "del", "dev", exitDeviceName)
}
