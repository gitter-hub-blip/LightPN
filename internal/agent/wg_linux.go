//go:build linux

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const deviceName = "lightpn0"

// wgIfaceName reports the WG device name for conf_result.
func wgIfaceName() string { return deviceName }

// linuxWG drives the kernel WireGuard module via wgctrl; interface
// creation and addressing use iproute2 (the only external dependency).
type linuxWG struct {
	mu     sync.Mutex
	client *wgctrl.Client
	priv   wgtypes.Key
	port   int
	// pubkey (base64) -> node ID, for heartbeat status mapping
	peerNodes map[string]string
	// node ID -> pubkey, to drop the stale key on peer_update
	nodeKeys map[string]string
}

// NewWGManager returns the Linux kernel implementation.
func NewWGManager() (WGManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl (is the wireguard kernel module loaded?): %w", err)
	}
	return &linuxWG{
		client:    client,
		peerNodes: map[string]string{},
		nodeKeys:  map[string]string{},
	}, nil
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (w *linuxWG) Init(overlayIP, overlayCIDR string, listenPort int) (string, int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// (Re)create the device from scratch: any leftover peers from a
	// previous process must not survive (invariant 2).
	if _, err := net.InterfaceByName(deviceName); err == nil {
		if err := ipCmd("link", "del", "dev", deviceName); err != nil {
			return "", 0, err
		}
	}
	if err := ipCmd("link", "add", deviceName, "type", "wireguard"); err != nil {
		return "", 0, err
	}

	// Address the device with the overlay CIDR's prefix length so the
	// kernel installs the connected route for the whole overlay.
	addr, err := overlayAddr(overlayIP, overlayCIDR)
	if err != nil {
		return "", 0, err
	}
	if err := ipCmd("addr", "replace", addr, "dev", deviceName); err != nil {
		return "", 0, err
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", 0, err
	}
	w.priv = priv
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        nil,
	}
	if err := w.client.ConfigureDevice(deviceName, cfg); err != nil {
		return "", 0, fmt.Errorf("configure %s: %w", deviceName, err)
	}
	if err := ipCmd("link", "set", "up", "dev", deviceName); err != nil {
		return "", 0, err
	}
	dev, err := w.client.Device(deviceName)
	if err != nil {
		return "", 0, err
	}
	w.port = dev.ListenPort
	w.peerNodes = map[string]string{}
	w.nodeKeys = map[string]string{}
	return priv.PublicKey().String(), dev.ListenPort, nil
}

// overlayAddr merges "100.100.0.7/32" with cidr "100.100.0.0/24" into
// "100.100.0.7/24".
func overlayAddr(overlayIP, overlayCIDR string) (string, error) {
	ipPart := strings.SplitN(overlayIP, "/", 2)[0]
	addr, err := netip.ParseAddr(ipPart)
	if err != nil {
		return "", err
	}
	prefix, err := netip.ParsePrefix(overlayCIDR)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", addr, prefix.Bits()), nil
}

func specToPeerConfig(spec proto.PeerSpec) (wgtypes.PeerConfig, error) {
	key, err := wgtypes.ParseKey(spec.WGPubkey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer pubkey: %w", err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", spec.Endpoint)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer endpoint %q: %w", spec.Endpoint, err)
	}
	var allowed []net.IPNet
	for _, cidr := range spec.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("allowed_ip %q: %w", cidr, err)
		}
		allowed = append(allowed, *ipnet)
	}
	keepalive := time.Duration(spec.KeepaliveS) * time.Second
	return wgtypes.PeerConfig{
		PublicKey:                   key,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowed,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: &keepalive,
	}, nil
}

func (w *linuxWG) Reconcile(specs []proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var peers []wgtypes.PeerConfig
	peerNodes := map[string]string{}
	nodeKeys := map[string]string{}
	for _, spec := range specs {
		pc, err := specToPeerConfig(spec)
		if err != nil {
			return err
		}
		peers = append(peers, pc)
		peerNodes[spec.WGPubkey] = spec.PeerNodeID
		nodeKeys[spec.PeerNodeID] = spec.WGPubkey
	}
	// ReplacePeers removes anything not in the list — the reconciliation
	// contract of §5.3.
	err := w.client.ConfigureDevice(deviceName, wgtypes.Config{
		ReplacePeers: true,
		Peers:        peers,
	})
	if err != nil {
		return err
	}
	w.peerNodes = peerNodes
	w.nodeKeys = nodeKeys
	return nil
}

func (w *linuxWG) AddPeer(spec proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addPeerLocked(spec)
}

func (w *linuxWG) addPeerLocked(spec proto.PeerSpec) error {
	pc, err := specToPeerConfig(spec)
	if err != nil {
		return err
	}
	if err := w.client.ConfigureDevice(deviceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}}); err != nil {
		return err
	}
	w.peerNodes[spec.WGPubkey] = spec.PeerNodeID
	w.nodeKeys[spec.PeerNodeID] = spec.WGPubkey
	return nil
}

func (w *linuxWG) UpdatePeer(spec proto.PeerSpec) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Drop the node's previous (stale) key first — peer_update semantics.
	if old, ok := w.nodeKeys[spec.PeerNodeID]; ok && old != spec.WGPubkey {
		if err := w.removeKeyLocked(old); err != nil {
			return err
		}
	}
	return w.addPeerLocked(spec)
}

func (w *linuxWG) RemovePeer(pubkeyB64 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.removeKeyLocked(pubkeyB64)
}

func (w *linuxWG) removeKeyLocked(pubkeyB64 string) error {
	key, err := wgtypes.ParseKey(pubkeyB64)
	if err != nil {
		return err
	}
	err = w.client.ConfigureDevice(deviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}},
	})
	if err != nil && !strings.Contains(err.Error(), "no such") {
		return err
	}
	if nodeID, ok := w.peerNodes[pubkeyB64]; ok {
		delete(w.peerNodes, pubkeyB64)
		if w.nodeKeys[nodeID] == pubkeyB64 {
			delete(w.nodeKeys, nodeID)
		}
	}
	return nil
}

func (w *linuxWG) Status() ([]proto.WGPeerStatus, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	dev, err := w.client.Device(deviceName)
	if err != nil {
		return nil, err
	}
	out := []proto.WGPeerStatus{}
	for _, p := range dev.Peers {
		st := proto.WGPeerStatus{
			PeerNodeID: w.peerNodes[p.PublicKey.String()],
			RxBytes:    uint64(p.ReceiveBytes),
			TxBytes:    uint64(p.TransmitBytes),
		}
		if !p.LastHandshakeTime.IsZero() {
			st.LastHandshakeTS = p.LastHandshakeTime.Unix()
		}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		out = append(out, st)
	}
	return out, nil
}

func (w *linuxWG) Rotate() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	err = w.client.ConfigureDevice(deviceName, wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true, // old peers refer to sessions on the old key
	})
	if err != nil {
		return "", err
	}
	w.priv = priv
	w.peerNodes = map[string]string{}
	w.nodeKeys = map[string]string{}
	return priv.PublicKey().String(), nil
}

func (w *linuxWG) Teardown() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := net.InterfaceByName(deviceName); err != nil {
		return nil
	}
	return ipCmd("link", "del", "dev", deviceName)
}
