package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gitter-hub-blip/lightpn/internal/proto"
)

// svcCmdWindow is the sealed-command freshness window (± seconds). Wide
// enough for edge-VPS clock drift, narrow enough that a captured command is
// useless shortly after; the IV cache blocks replays inside the window.
const svcCmdWindow = 300

// svcCmd is the browser-sealed command plaintext.
type svcCmd struct {
	Action string `json:"action"`
	Alias  string `json:"alias"`
	TS     int64  `json:"ts"`
}

// openSvcCmd authenticates and unwraps a sealed service command. Order
// matters: GCM open first (proves the sender holds the view password —
// without this a compromised hub could issue commands for known aliases),
// then action allow-list, freshness window, and replay check.
func (a *Agent) openSvcCmd(d proto.SvcActionData, now int64) (*svcCmd, error) {
	vk, err := loadViewKey(a.ID.Dir)
	if err != nil {
		return nil, fmt.Errorf("view key unreadable: %w", err)
	}
	if vk == nil {
		return nil, errors.New("no view password configured — service control disabled")
	}
	key, err := base64.StdEncoding.DecodeString(vk.Key)
	if err != nil || len(key) != viewKeyLen {
		return nil, errors.New("malformed view.key key material")
	}
	nonce, err := base64.StdEncoding.DecodeString(d.Nonce)
	if err != nil {
		return nil, errors.New("bad nonce encoding")
	}
	ct, err := base64.StdEncoding.DecodeString(d.CT)
	if err != nil {
		return nil, errors.New("bad ciphertext encoding")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce length")
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("command authentication failed")
	}
	cmd := &svcCmd{}
	if err := json.Unmarshal(plain, cmd); err != nil {
		return nil, errors.New("malformed command payload")
	}
	if !svcActions[cmd.Action] {
		return nil, fmt.Errorf("action %q not allowed", cmd.Action)
	}
	if cmd.TS < now-svcCmdWindow || cmd.TS > now+svcCmdWindow {
		return nil, errors.New("command expired (check clocks)")
	}
	// Replay cache keyed by IV; entries outside the window are pruned, so
	// the map stays bounded by the command rate within ±window.
	a.svcMu.Lock()
	defer a.svcMu.Unlock()
	if a.svcSeen == nil {
		a.svcSeen = map[string]int64{}
	}
	for iv, ts := range a.svcSeen {
		if ts < now-2*svcCmdWindow {
			delete(a.svcSeen, iv)
		}
	}
	if _, dup := a.svcSeen[d.Nonce]; dup {
		return nil, errors.New("replayed command rejected")
	}
	a.svcSeen[d.Nonce] = cmd.TS
	return cmd, nil
}

// handleSvcAction executes a sealed command end to end and always returns a
// result (errors travel inside SvcResultData, not as protocol errors).
func (a *Agent) handleSvcAction(d proto.SvcActionData, now int64) proto.SvcResultData {
	cmd, err := a.openSvcCmd(d, now)
	if err != nil {
		a.Log.Warn("svc_action rejected", "err", err)
		return proto.SvcResultData{Err: err.Error(), Services: a.collectSvcStatus()}
	}
	unit, err := lookupSvc(a.ID.Dir, cmd.Alias)
	if err != nil {
		a.Log.Warn("svc_action unknown alias", "alias", cmd.Alias)
		return proto.SvcResultData{Err: err.Error(), Services: a.collectSvcStatus()}
	}
	if a.Svc == nil {
		return proto.SvcResultData{Err: "service control unavailable on this build"}
	}
	err = a.Svc.Do(cmd.Action, unit)
	a.Log.Info("svc_action executed", "action", cmd.Action, "alias", cmd.Alias, "err", err)
	res := proto.SvcResultData{OK: err == nil, Services: a.collectSvcStatus()}
	if err != nil {
		res.Err = err.Error()
	}
	return res
}
