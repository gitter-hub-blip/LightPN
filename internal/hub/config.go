package hub

import (
	"encoding/json"
	"os"
	"time"
)

// Config collects all hub tunables. The time constants (heartbeat, dead
// detection, peer GC) are deliberately defined in one place — see §12.
type Config struct {
	DataDir     string `json:"data_dir"`     // SQLite + CA live here
	ControlAddr string `json:"control_addr"` // mTLS control channel, public
	APIAddr     string `json:"api_addr"`     // admin API + panel, loopback only
	OverlayCIDR string `json:"overlay_cidr"`
	// PublicAddr is the address agents are told to reconnect to
	// (host:port). Defaults to the enrollment connection's local address.
	PublicAddr string `json:"public_addr"`
	// SecureCookie marks the panel session cookie Secure. The default (true)
	// works both behind the Cloudflare HTTPS edge and for plain-HTTP loopback
	// debugging (browsers treat localhost as a secure context); disable only
	// if a non-localhost plain-HTTP origin must reach the panel directly.
	SecureCookie bool `json:"secure_cookie"`

	HeartbeatS  int `json:"heartbeat_s"`   // agent heartbeat period
	DeadAfterS  int `json:"dead_after_s"`  // mark offline after this silence
	PeerGCAfterS int `json:"peer_gc_after_s"` // remove peers from others after offline this long
	KeepaliveS  int `json:"keepalive_s"`   // WG persistent keepalive pushed to agents
	TokenTTLs   int `json:"token_ttl_s"`   // default enrollment token TTL
	CertTTLDays int `json:"cert_ttl_days"` // agent client cert validity
	IPCooldownS int `json:"ip_cooldown_s"` // freed overlay IP quarantine
}

// Defaults returns the documented default configuration.
func Defaults() Config {
	return Config{
		DataDir:      "/var/lib/lightpn/hub",
		ControlAddr:  "0.0.0.0:7440",
		APIAddr:      "127.0.0.1:7441",
		SecureCookie: true,
		OverlayCIDR:  "100.100.0.0/24",
		HeartbeatS:   15,
		DeadAfterS:   45,
		PeerGCAfterS: 300,
		KeepaliveS:   25,
		TokenTTLs:    900,
		CertTTLDays:  365,
		IPCooldownS:  30 * 24 * 3600,
	}
}

// LoadConfig reads a JSON config file over the defaults; a missing file
// just yields the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) HeartbeatPeriod() time.Duration { return time.Duration(c.HeartbeatS) * time.Second }
func (c Config) DeadAfter() time.Duration       { return time.Duration(c.DeadAfterS) * time.Second }
func (c Config) PeerGCAfter() time.Duration     { return time.Duration(c.PeerGCAfterS) * time.Second }
func (c Config) TokenTTL() time.Duration        { return time.Duration(c.TokenTTLs) * time.Second }
func (c Config) IPCooldown() time.Duration      { return time.Duration(c.IPCooldownS) * time.Second }
