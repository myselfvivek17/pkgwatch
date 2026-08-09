// Package config loads pkgwatch's TOML configuration and resolves platform data paths.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

// Default ports. The hub dashboard and an agent's local dashboard both want
// 4875; when they are co-resident the agent shifts to DashboardPortAlt (§2).
const (
	DefaultNPMPort       = 4873
	DefaultPyPIPort      = 4874
	DefaultDashboardPort = 4875
	DashboardPortAlt     = 4877
)

type Config struct {
	DataDir string      `toml:"data_dir"`
	Agent   AgentConfig `toml:"agent"`
	Hub     HubConfig   `toml:"hub"`
}

type AgentConfig struct {
	Bind          string `toml:"bind"`
	NPMPort       int    `toml:"npm_port"`
	PyPIPort      int    `toml:"pypi_port"`
	DashboardPort int    `toml:"dashboard_port"`

	// CooldownHours treats any version published more recently than this as
	// prompt-worthy regardless of advisories — advisories lag attacks (§5.1).
	//
	// Non-zero also makes the npm gate request full packuments rather than the
	// abbreviated ones npm asks for, because only the full document carries
	// publish times. Set to 0 for smaller registry responses and no cooldown.
	CooldownHours int `toml:"cooldown_hours"`

	// BlockTier is the lowest finding tier that stops an install. Malware always
	// blocks regardless — it is an active attack, not a latent weakness, and the
	// two do not share a scale.
	//
	// Default high, not medium: npm's corpus has a low or medium advisory
	// against a large share of transitive dependencies, and a gate that fires on
	// all of them gets switched off in a week.
	BlockTier string `toml:"block_tier"`

	// Registry upstreams. Empty means the public registry.
	NPMUpstream  string `toml:"npm_upstream"`
	PyPIUpstream string `toml:"pypi_upstream"`

	// SyncLevel is one of findings|full|off. Default findings: sending the full
	// inventory hands the hub a map of exploitable software on every machine,
	// which should be a conscious choice (§3.3).
	SyncLevel string `toml:"sync_level"`

	HubURL string `toml:"hub_url"`
}

type HubConfig struct {
	Bind string `toml:"bind"`
	Port int    `toml:"port"`

	// PasswordHash is argon2id. The hub binds a non-loopback address, and this
	// UI deletes files and approves package installs — unauthenticated on a LAN
	// it is a remote code execution primitive, so startup refuses without it (§8).
	PasswordHash string `toml:"password_hash"`
}

func Default() Config {
	return Config{
		Agent: AgentConfig{
			Bind:          "127.0.0.1",
			NPMPort:       DefaultNPMPort,
			PyPIPort:      DefaultPyPIPort,
			DashboardPort: DefaultDashboardPort,
			CooldownHours: 24,
			BlockTier:     "high",
			SyncLevel:     "findings",
		},
		Hub: HubConfig{
			Bind: "0.0.0.0",
			Port: DefaultDashboardPort,
		},
	}
}

// Load reads path over the defaults. A missing file is not an error — a fresh
// machine runs entirely on defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return withResolvedDataDir(cfg)
		}
		return cfg, fmt.Errorf("stat config %s: %w", path, err)
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return withResolvedDataDir(cfg)
}

func withResolvedDataDir(cfg Config) (Config, error) {
	if cfg.DataDir == "" {
		dir, err := DataDir()
		if err != nil {
			return cfg, err
		}
		cfg.DataDir = dir
	}
	return cfg, nil
}

func DefaultPath() string {
	dir, err := DataDir()
	if err != nil {
		return "pkgwatch.toml"
	}
	return filepath.Join(dir, "pkgwatch.toml")
}

// DataDir resolves the per-platform data directory. No single stdlib helper
// gives all three of the paths the spec names, so switch on GOOS:
//
//	Linux    ~/.local/share/pkgwatch      (os.UserCacheDir would give ~/.cache)
//	macOS    ~/Library/Application Support/pkgwatch
//	Windows  %LOCALAPPDATA%\pkgwatch      (os.UserConfigDir would give Roaming)
func DataDir() (string, error) {
	var base string
	var err error
	switch runtime.GOOS {
	case "windows":
		base, err = os.UserCacheDir() // %LocalAppData%
	case "darwin":
		base, err = os.UserConfigDir() // ~/Library/Application Support
	default:
		if x := os.Getenv("XDG_DATA_HOME"); x != "" {
			base = x
		} else {
			var home string
			home, err = os.UserHomeDir()
			base = filepath.Join(home, ".local", "share")
		}
	}
	if err != nil {
		return "", fmt.Errorf("resolve data dir: %w", err)
	}
	return filepath.Join(base, "pkgwatch"), nil
}

// AgentDBPath, HubDBPath and AdvisoryDBPath live side by side in DataDir.
// advisories.db is deliberately a separate file so a bundle update is an atomic
// file swap rather than a migration (§3.2).
func (c Config) AgentDBPath() string    { return filepath.Join(c.DataDir, "agent.db") }
func (c Config) HubDBPath() string      { return filepath.Join(c.DataDir, "hub.db") }
func (c Config) AdvisoryDBPath() string { return filepath.Join(c.DataDir, "advisories.db") }
func (c Config) QuarantineDir() string  { return filepath.Join(c.DataDir, "quarantine") }
