// Package config loads pkgwatch's TOML configuration and resolves platform data paths.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/myselfvivek17/pkgwatch/internal/match"

	"github.com/myselfvivek17/pkgwatch/internal/bundle"
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

	// CooldownHours is the publish buffer: a version released more recently than
	// this is withheld from resolution, so the resolver settles on the previous
	// one (§5.1).
	//
	// This is the only defence that needs no knowledge at all, and it covers the
	// window nothing else can. Every advisory postdates the attack it describes,
	// so a compromised release is indistinguishable from a good one for its first
	// hours — which is exactly when it is being installed.
	//
	// Three days by default: long enough that most compromises are caught and
	// pulled, short enough to be worth leaving switched on. The buffer never
	// applies when nothing older survives, so a brand new package and a security
	// patch both still install.
	//
	// Non-zero also makes the npm gate request full packuments rather than the
	// abbreviated ones npm asks for, because only the full document carries
	// publish times. Set to 0 for smaller registry responses and no buffer.
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

	// HistoryDays is how long recorded verdicts and timeline events are kept.
	//
	// A single npm install writes roughly 1,200 gate decisions, so without a
	// retention pass the audit trail outgrows everything else in the database by
	// two orders of magnitude. Routine "allowed" decisions are bounded by recent
	// session count instead; this window governs the verdicts that stopped
	// something, which are what an incident is reconstructed from.
	HistoryDays int `toml:"history_days"`

	// PromoteTiers lets install context raise a finding's tier, as §5.2
	// originally specified: a medium advisory in a globally installed package
	// with lifecycle scripts becomes critical.
	//
	// Off by default. Both readings are defensible, but with it on, "critical"
	// means something different on two machines in the same fleet — on one
	// laptop 92% of criticals came from these multipliers rather than from any
	// advisory rating a package critical, while the home server's came entirely
	// from real 9.8s. The multipliers still set the score either way, so
	// context still decides what sorts to the top; this only governs what the
	// badge claims.
	PromoteTiers bool `toml:"promote_tiers"`

	// ScanIntervalHours is how often the daemon re-scans and re-matches.
	//
	// The whole retroactive half of this tool depends on running without being
	// asked: the package you installed six months ago that became known-bad this
	// morning is only found by a pass nobody triggered. A scan costs a few
	// hundred milliseconds, so the interval is about noticing promptly rather
	// than about cost. Set to 0 to disable.
	ScanIntervalHours int `toml:"scan_interval_hours"`

	// ScanPaths are the project trees an unattended scan walks.
	//
	// Empty by default and deliberately so: there is no safe guess at where
	// someone's projects live, and walking a home directory to find out is slow
	// enough that nobody would leave it switched on. Machine-wide installs,
	// containers and the host's own packages are always scanned regardless.
	ScanPaths []string `toml:"scan_paths"`

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

	// TLS is on by default, and turning it off puts the dashboard password on
	// the wire in a plaintext form POST to a listener the whole LAN can reach.
	//
	// A pointer so "unset" is distinguishable from "explicitly false": the
	// default has to be on, and a zero-value bool cannot express that.
	TLS *bool `toml:"tls"`

	// TLSCert and TLSKey point at a real certificate if there is one. Left
	// empty, the hub generates a self-signed pair into the data directory on
	// first run — agents pin whatever is presented at pairing either way, so
	// this is about what a browser says, not about the sync protocol.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
}

// TLSEnabled reports whether the hub should serve https. Default on.
func (h HubConfig) TLSEnabled() bool { return h.TLS == nil || *h.TLS }

func Default() Config {
	return Config{
		Agent: AgentConfig{
			Bind:              "127.0.0.1",
			NPMPort:           DefaultNPMPort,
			PyPIPort:          DefaultPyPIPort,
			DashboardPort:     DefaultDashboardPort,
			CooldownHours:     72,
			BlockTier:         "high",
			HistoryDays:       90,
			ScanIntervalHours: 6,
			SyncLevel:         "findings",
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
			applyScoringPolicy(cfg)
			return withResolvedDataDir(cfg)
		}
		return cfg, fmt.Errorf("stat config %s: %w", path, err)
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyScoringPolicy(cfg)
	return withResolvedDataDir(cfg)
}

// applyScoringPolicy pushes the tier policy into the matcher.
//
// It lives on a package variable rather than being threaded through every
// Score call because scoring happens in the gate, the watcher and the CLI, and
// every one of them would otherwise carry a parameter it does not otherwise
// need. Set once at load, read everywhere — the same value on every path, which
// is the property that actually matters.
func applyScoringPolicy(cfg Config) {
	match.PromoteTiers = cfg.Agent.PromoteTiers
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

// BundleDir holds the verified per-scope bundles the merged advisories.db is
// built from. They are kept rather than discarded: they are what was actually
// signed, and without them changing one ecosystem would mean re-downloading
// every other.
func (c Config) BundleDir() string { return filepath.Join(c.DataDir, "bundles") }

// ScopedBundlePath is where the bundle for one scope is stored. The filename is
// a convenience; the scope that counts is the one inside the signature.
func (c Config) ScopedBundlePath(scope string) string {
	return filepath.Join(c.BundleDir(), "advisories-"+bundle.ScopeFileName(scope)+".db")
}

// ScopedBundles lists every verified source bundle held locally.
func (c Config) ScopedBundles() ([]string, error) {
	entries, err := os.ReadDir(c.BundleDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".db") {
			out = append(out, filepath.Join(c.BundleDir(), entry.Name()))
		}
	}
	return out, nil
}
