package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// The service registry maps operator-chosen aliases to systemd unit names.
// It is written ONLY by the local CLI (svc-add/svc-del, root on the box) —
// the hub has no path that creates, edits, or deletes entries, and only the
// aliases ever go on the wire. This is the capability model: the hub can
// refer to exactly what the operator chose to expose, nothing else.

var (
	aliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	unitRE  = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)
)

// SvcEntry is one registered service.
type SvcEntry struct {
	Alias string `json:"alias"`
	Unit  string `json:"unit"`
}

func svcRegPath(dir string) string { return filepath.Join(dir, "services.json") }

// LoadSvcReg reads the registry; an absent file is an empty registry.
func LoadSvcReg(dir string) ([]SvcEntry, error) {
	data, err := os.ReadFile(svcRegPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reg []SvcEntry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("malformed services.json: %w", err)
	}
	return reg, nil
}

func saveSvcReg(dir string, reg []SvcEntry) error {
	sort.Slice(reg, func(i, j int) bool { return reg[i].Alias < reg[j].Alias })
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(svcRegPath(dir), data, 0o600)
}

// AddSvc validates and registers alias→unit. The unit name is checked
// against a strict pattern here and never taken from the wire anywhere.
func AddSvc(dir, alias, unit string) error {
	if !aliasRE.MatchString(alias) {
		return errors.New("别名须为 1-32 位小写字母/数字/连字符,且以字母或数字开头")
	}
	if !unitRE.MatchString(unit) {
		return errors.New("unit 名须形如 xxx.service(字母/数字/._@- 组成)")
	}
	reg, err := LoadSvcReg(dir)
	if err != nil {
		return err
	}
	for _, e := range reg {
		if e.Alias == alias {
			return fmt.Errorf("别名 %s 已登记为 %s", alias, e.Unit)
		}
		if e.Unit == unit {
			return fmt.Errorf("unit %s 已登记为别名 %s", unit, e.Alias)
		}
	}
	return saveSvcReg(dir, append(reg, SvcEntry{Alias: alias, Unit: unit}))
}

// DelSvc removes a registration by alias.
func DelSvc(dir, alias string) error {
	reg, err := LoadSvcReg(dir)
	if err != nil {
		return err
	}
	kept := reg[:0]
	for _, e := range reg {
		if e.Alias != alias {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(reg) {
		return fmt.Errorf("别名 %s 未登记", alias)
	}
	return saveSvcReg(dir, kept)
}

// lookupSvc resolves an alias from a sealed command to its unit.
func lookupSvc(dir, alias string) (string, error) {
	reg, err := LoadSvcReg(dir)
	if err != nil {
		return "", err
	}
	for _, e := range reg {
		if e.Alias == alias {
			return e.Unit, nil
		}
	}
	return "", fmt.Errorf("alias %q not registered", alias)
}

// DetectSvcCandidates returns which of the compiled-in candidate units
// exist on this system — svc-add input hints, nothing more.
func DetectSvcCandidates(svc SvcManager) []string {
	var found []string
	for _, u := range svcCandidateUnits {
		if svc.Exists(u) {
			found = append(found, u)
		}
	}
	return found
}

// svcCandidateUnits are common proxy-tool unit names offered as SUGGESTIONS
// by the svc-add CLI (like toolConfCandidates, compiled in). They are input
// hints only: nothing is registered without the operator confirming.
var svcCandidateUnits = []string{
	"xray.service",
	"sing-box.service",
	"v2ray.service",
	"hysteria.service",
	"hysteria-server.service",
	"trojan-go.service",
	"shadowsocks-rust.service",
	"ssserver.service",
	"mihomo.service",
	"clash.service",
}
