package agent

import (
	"os"
	"strings"

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
// into an arbitrary-file read. Tools at other locations are covered by the
// svc registry's per-entry conf path (svc-add, local CLI only).
// Package-level so tests can substitute it.
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
	{"caddy", "/etc/caddy/Caddyfile"}, // naive 常经 caddy forward_proxy 部署
	{"naiveproxy", "/etc/naiveproxy/config.json"},
}

// collectToolConf answers conf_get: the WG runtime summary (no private key,
// invariant 2), every candidate config file that exists, and every conf path
// registered via svc-add. Missing candidate paths are silently skipped (tool
// not installed); a registered path was promised by the operator, so its
// stat/read failure is reported with Err — the panel can then distinguish
// "not installed" from "path wrong / permission denied".
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

	type candidate struct {
		tool, path string
		registered bool
	}
	// Registered paths scan FIRST: when a registry entry and a builtin
	// candidate name the same file, the file belongs to the service (the
	// panel draws one bar per service, keyed by the registered flag +
	// alias). Builtins only pick up paths no service has claimed.
	cands := make([]candidate, 0, len(toolConfCandidates)+4)
	if a.ID != nil {
		if reg, err := LoadSvcReg(a.ID.Dir); err == nil {
			for _, e := range reg {
				if e.Conf != "" {
					cands = append(cands, candidate{e.Alias, e.Conf, true})
				}
			}
		} else if a.Log != nil {
			a.Log.Warn("services.json unreadable, registered conf paths skipped", "err", err)
		}
	}
	for _, c := range toolConfCandidates {
		cands = append(cands, candidate{c.tool, c.path, false})
	}

	total := 0
	seen := map[string]bool{} // paths already emitted (a builtin may repeat a registered one)
	for _, c := range cands {
		if seen[c.path] {
			continue
		}
		fi, err := os.Stat(c.path)
		if err != nil || fi.IsDir() {
			if c.registered {
				msg := "登记的是目录,目前只支持单个文件"
				if err != nil {
					msg = err.Error()
				}
				out.Files = append(out.Files, proto.ConfFile{Tool: c.tool, Path: c.path, Err: msg, Registered: true})
				seen[c.path] = true
			}
			continue
		}
		seen[c.path] = true
		f := proto.ConfFile{Tool: c.tool, Path: c.path, ModTime: fi.ModTime().Unix(), Size: fi.Size(), Registered: c.registered}
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
	if a.Log != nil {
		paths := make([]string, len(out.Files))
		for i, f := range out.Files {
			paths[i] = f.Path
			if f.Err != "" {
				paths[i] += "(err)"
			}
		}
		a.Log.Info("tool conf collected", "files", len(out.Files), "paths", strings.Join(paths, " "))
	}
	return out
}
