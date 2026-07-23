package agent

import (
	"os"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// Per-file and total caps keep the conf_result frame well under the 1 MiB
// protocol frame limit even with several tools installed.
const (
	confFileCap  = 256 << 10 // per file
	confTotalCap = 768 << 10 // sum of all file contents
)

// toolConfCandidates are the well-known config locations of common proxy
// tools. Auto-detection only: the agent reads exactly these paths and never
// takes a path from the wire, so a compromised hub cannot turn conf_get
// into an arbitrary-file read. Package-level so tests can substitute it.
var toolConfCandidates = []struct{ tool, path string }{
	{"xray", "/usr/local/etc/xray/config.json"},
	{"xray", "/etc/xray/config.json"},
	{"sing-box", "/etc/sing-box/config.json"},
	{"sing-box", "/usr/local/etc/sing-box/config.json"},
	{"v2ray", "/usr/local/etc/v2ray/config.json"},
	{"v2ray", "/etc/v2ray/config.json"},
	{"hysteria", "/etc/hysteria/config.yaml"},
	{"hysteria", "/etc/hysteria/config.json"},
	{"trojan-go", "/etc/trojan-go/config.json"},
	{"shadowsocks-rust", "/etc/shadowsocks-rust/config.json"},
	{"shadowsocks-rust", "/usr/local/etc/shadowsocks-rust/config.json"},
	{"shadowsocks", "/etc/shadowsocks/config.json"},
	{"mihomo", "/etc/mihomo/config.yaml"},
	{"clash", "/etc/clash/config.yaml"},
}

// collectToolConf answers conf_get: the WG runtime summary (no private key,
// invariant 2) plus every candidate config file that exists. Missing paths
// are silently skipped; unreadable ones are reported with Err so the panel
// can distinguish "not installed" from "permission denied".
func (a *Agent) collectToolConf() proto.ConfResultData {
	out := proto.ConfResultData{
		WG: proto.ConfWG{
			Iface:      wgIfaceName(),
			Pubkey:     a.wgPub,
			ListenPort: a.wgListenPort,
		},
	}
	if peers, err := a.WG.Status(); err == nil {
		out.WG.Peers = peers
	}

	total := 0
	for _, c := range toolConfCandidates {
		fi, err := os.Stat(c.path)
		if err != nil || fi.IsDir() {
			continue
		}
		f := proto.ConfFile{Tool: c.tool, Path: c.path, ModTime: fi.ModTime().Unix(), Size: fi.Size()}
		switch data, err := os.ReadFile(c.path); {
		case err != nil:
			f.Err = err.Error()
		default:
			if len(data) > confFileCap {
				data = data[:confFileCap]
				f.Truncated = true
			}
			if total+len(data) > confTotalCap {
				data = data[:confTotalCap-total]
				f.Truncated = true
			}
			f.Content = string(data)
			total += len(data)
		}
		out.Files = append(out.Files, f)
		if total >= confTotalCap {
			break
		}
	}
	return out
}
