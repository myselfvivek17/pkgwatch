package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Setting is one configurable value, as it actually stands.
//
// FromFile is the field that makes this worth rendering at all. A sparse config
// over code defaults means the effective value of anything is unanswerable
// without reading the source, and "72" tells you nothing about whether somebody
// chose 72 or simply never touched it.
type Setting struct {
	Key      string
	Value    string
	FromFile bool

	// Effect says where the value is read, and — for anything bound once at
	// startup — that a change needs a restart. A settings page that shows a
	// value without saying when it applies invites the assumption that editing
	// the file is enough.
	Effect string

	// Note is one line on what the setting is for.
	Note string
}

// Source describes where the value came from, for display.
func (s Setting) Source() string {
	if s.FromFile {
		return "set in config"
	}
	return "default"
}

// Section groups settings the way the TOML file does.
type Section struct {
	Title    string
	Note     string
	Settings []Setting
}

// Explain reports the effective configuration and where each value came from.
//
// Read-only by design. The agent's dashboard is unauthenticated on loopback —
// that is safe only because it cannot change how this machine is protected, and
// a write path to `bind` in particular would turn "anything running on this
// box" into "anything on the LAN". If writes are ever added here, bind, the
// ports, password_hash and the TLS paths must stay out of them.
func Explain(cfg Config, path, mode string) []Section {
	if path == "" {
		path = DefaultPath()
	}

	// Decoded a second time purely for the metadata: Load returns the merged
	// result, which cannot say which keys were present. A parse failure here is
	// not fatal — the daemon is already running on this file — so everything
	// simply reports as a default rather than the page refusing to render.
	var meta toml.MetaData
	if _, err := os.Stat(path); err == nil {
		var discard Config
		if md, err := toml.DecodeFile(path, &discard); err == nil {
			meta = md
		}
	}
	set := func(keys ...string) bool { return meta.IsDefined(keys...) }

	a := cfg.Agent
	agent := Section{
		Title: "Gate",
		Note:  "What stops an install, and what it asks upstream.",
		Settings: []Setting{
			{Key: "agent.block_tier", Value: a.BlockTier, FromFile: set("agent", "block_tier"),
				Effect: "gate verdicts, read per install",
				Note:   "lowest tier that stops an install; malware always blocks regardless"},
			{Key: "agent.cooldown_hours", Value: hours(a.CooldownHours), FromFile: set("agent", "cooldown_hours"),
				Effect: "npm gate, read per request",
				Note:   "versions published more recently than this are withheld from resolution"},
			{Key: "agent.npm_upstream", Value: orPublic(a.NPMUpstream), FromFile: set("agent", "npm_upstream"),
				Effect: "npm gate", Note: "where the proxy fetches from"},
			{Key: "agent.pypi_upstream", Value: orPublic(a.PyPIUpstream), FromFile: set("agent", "pypi_upstream"),
				Effect: "PyPI index", Note: "where the index is fetched from"},
		},
	}

	scanning := Section{
		Title: "Scanning and advisories",
		Note:  "The half of this tool that runs without being asked.",
		Settings: []Setting{
			{Key: "agent.scan_interval_hours", Value: hours(a.ScanIntervalHours), FromFile: set("agent", "scan_interval_hours"),
				Effect: "unattended scan loop", Note: "0 disables it; the retroactive half depends on this"},
			{Key: "agent.scan_paths", Value: list(a.ScanPaths), FromFile: set("agent", "scan_paths"),
				Effect: "unattended scan loop",
				Note:   "project trees to walk; machine-wide, container and host packages are scanned regardless"},
			{Key: "agent.bundle_interval_hours", Value: hours(a.BundleIntervalHours), FromFile: set("agent", "bundle_interval_hours"),
				Effect: "bundle updates",
				Note:   "0 means advisories only move when someone runs `pkgwatch sync` by hand"},
			{Key: "agent.promote_tiers", Value: yesNo(a.PromoteTiers), FromFile: set("agent", "promote_tiers"),
				Effect: "scoring, on every path",
				Note:   "lets install context raise a tier, not just the score"},
			{Key: "agent.history_days", Value: days(a.HistoryDays), FromFile: set("agent", "history_days"),
				Effect: "retention pass", Note: "how long gate verdicts and timeline events are kept"},
		},
	}

	fleetNote := "Outbound only. Nothing here lets a hub change how this machine behaves."
	fleet := Section{
		Title: "Fleet",
		Note:  fleetNote,
		Settings: []Setting{
			{Key: "agent.sync_level", Value: a.SyncLevel, FromFile: set("agent", "sync_level"),
				Effect: "fleet sync",
				Note:   "findings|full|off — full also requires the hub to accept this device's inventory"},
			{Key: "agent.hub_url", Value: orNone(a.HubURL), FromFile: set("agent", "hub_url"),
				Effect: "pairing", Note: "the paired hub is stored in the database; this only seeds it"},
		},
	}

	// Ports and binds are grouped apart from everything else because they share
	// one property nothing above has: they are claimed once at startup, so the
	// file and the running process can disagree.
	listeners := Section{
		Title: "Listeners",
		Note:  "Bound once at startup — editing these takes effect on restart, not on save.",
		Settings: []Setting{
			{Key: "agent.bind", Value: a.Bind, FromFile: set("agent", "bind"),
				Effect: "restart", Note: "loopback by default; the dashboard has no login of its own"},
			{Key: "agent.dashboard_port", Value: strconv.Itoa(a.DashboardPort), FromFile: set("agent", "dashboard_port"),
				Effect: "restart", Note: "shifts by two when this machine also runs a hub"},
			{Key: "agent.npm_port", Value: strconv.Itoa(a.NPMPort), FromFile: set("agent", "npm_port"),
				Effect: "restart", Note: "the npm registry proxy"},
			{Key: "agent.pypi_port", Value: strconv.Itoa(a.PyPIPort), FromFile: set("agent", "pypi_port"),
				Effect: "restart", Note: "the PyPI index"},
		},
	}

	if mode == "hub" {
		h := cfg.Hub
		return []Section{
			{
				Title: "Hub",
				Note:  "This hub aggregates the fleet. It never sends instructions back down.",
				Settings: []Setting{
					{Key: "hub.bind", Value: h.Bind, FromFile: set("hub", "bind"),
						Effect: "restart", Note: "0.0.0.0 exposes it on every interface, including container bridges"},
					{Key: "hub.port", Value: strconv.Itoa(h.Port), FromFile: set("hub", "port"),
						Effect: "restart", Note: "agents and the dashboard share this port"},
					{Key: "hub.tls", Value: yesNo(h.TLSEnabled()), FromFile: set("hub", "tls"),
						Effect: "restart",
						Note:   "on by default; agents pin the certificate fingerprint at pairing"},
					// Never the hash itself. It is not a secret worth much on its
					// own, but a dashboard that prints credential material trains
					// people to expect that, and the next one will matter.
					{Key: "hub.password_hash", Value: setOrNot(h.PasswordHash != ""), FromFile: set("hub", "password_hash"),
						Effect: "dashboard login",
						Note:   "argon2id; set it with `pkgwatch hub set-password`, never by hand"},
					{Key: "hub.tls_cert", Value: orGenerated(h.TLSCert), FromFile: set("hub", "tls_cert"),
						Effect: "restart", Note: "self-signed and generated into the data dir when unset"},
					{Key: "hub.tls_key", Value: orGenerated(h.TLSKey), FromFile: set("hub", "tls_key"),
						Effect: "restart", Note: "kept 0600 beside the certificate"},
				},
			},
		}
	}

	return []Section{agent, scanning, fleet, listeners}
}

func hours(n int) string {
	if n == 0 {
		return "0 (off)"
	}
	return fmt.Sprintf("%d hours", n)
}

func days(n int) string {
	if n == 0 {
		return "0 (kept forever)"
	}
	return fmt.Sprintf("%d days", n)
}

func list(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func yesNo(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orPublic(s string) string {
	if s == "" {
		return "the public registry"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orGenerated(s string) string {
	if s == "" {
		return "generated"
	}
	return s
}

func setOrNot(b bool) string {
	if b {
		return "set"
	}
	return "not set"
}
