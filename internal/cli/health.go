package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/hub"
)

func healthCmd() *cobra.Command {
	var url string

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Ask the running daemon whether it is serving",
		Long: "Fetch /health from the daemon on this machine and exit non-zero if it does not answer.\n\n" +
			"Distinct from `pkgwatch status`, which reads the database and would report a\n" +
			"healthy machine while the listener was dead — the gate down, nothing scanning,\n" +
			"and every check that looked at the process saying fine. This asks the socket.\n\n" +
			"Built for supervisors: a container healthcheck, a systemd watchdog, or a task\n" +
			"that needs to know the difference between running and working.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			targets := healthTargets(cfg)
			if url != "" {
				targets = []target{{
					label: "given", url: url, tls: strings.HasPrefix(url, "https://"),
				}}
			}

			out := cmd.OutOrStdout()
			var failed []string
			for _, t := range targets {
				report, err := ask(cfg, t)
				if err != nil {
					// Printed, not returned, so a machine running two daemons
					// reports on both rather than stopping at the first dead
					// one — which would hide whether the other was up.
					fmt.Fprintf(out, "%-5s FAIL  %v\n", t.label, err)
					failed = append(failed, t.label)
					continue
				}
				fmt.Fprintf(out, "%-5s ok    %s\n", t.label, report)
			}
			if len(failed) > 0 {
				return fmt.Errorf("not serving: %s", strings.Join(failed, ", "))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&url, "url", "", "health endpoint to check (default: this machine's daemon)")
	return cmd
}

// pinnedToOwnCert builds a transport that trusts exactly the hub's own certificate.
//
// Not InsecureSkipVerify on its own. The certificate is self-signed, so ordinary
// verification cannot pass — but skipping verification outright would make this
// command answer "ok" for whatever process happened to be holding the port,
// which is precisely the confusion a health check exists to remove. The hub
// generated the keypair into its data directory; this reads that file and
// requires the listener to present it.
func pinnedToOwnCert(cfg config.Config) (*http.Transport, error) {
	certPath, _ := hub.CertPaths(cfg)
	encoded, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read the hub's certificate at %s, so there is nothing to "+
			"check the listener against: %w", certPath, err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM certificate", certPath)
	}
	expected := fleet.Fingerprint(block.Bytes)

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			// Paired with VerifyPeerCertificate below, never on its own: the
			// hub is reached by address rather than by a name any CA vouched
			// for, so the fingerprint is the whole check.
			InsecureSkipVerify: true, //nolint:gosec // VerifyPeerCertificate below is the check
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("the listener presented no certificate")
				}
				if got := fleet.Fingerprint(rawCerts[0]); !fleet.SameFingerprint(expected, got) {
					return fmt.Errorf(
						"something is listening on the hub's port that is not the hub: "+
							"expected certificate %s, got %s", expected, got)
				}
				return nil
			},
		},
	}, nil
}

// ask fetches one endpoint and summarises what it said.
func ask(cfg config.Config, t target) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	if t.tls {
		transport, err := pinnedToOwnCert(cfg)
		if err != nil {
			return "", err
		}
		client.Transport = transport
	}

	resp, err := client.Get(t.url)
	if err != nil {
		return "", fmt.Errorf("no answer from %s: %w", t.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s", t.url, resp.Status)
	}

	var body struct {
		OK      bool   `json:"ok"`
		Mode    string `json:"mode"`
		DB      string `json:"db"`
		Bundle  string `json:"bundle_version"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("%s answered something that is not a health report: %w", t.url, err)
	}
	// A 200 carrying ok:false is the case worth catching: the daemon is
	// listening and telling you its database is gone.
	if !body.OK {
		return "", fmt.Errorf("%s reports not ok (db %q)", t.url, body.DB)
	}

	return fmt.Sprintf("%s %s · db %s · bundle %s",
		body.Mode, body.Version, body.DB, orDash(body.Bundle)), nil
}

// target is one daemon to ask.
type target struct {
	label string
	url   string
	tls   bool
}

// healthTargets lists every daemon this config describes.
//
// Both, when a machine runs both: this box runs an agent and a hub, and a check
// that picked one of them would answer "healthy" while the other was down —
// which is the failure mode the command exists to catch, reproduced inside the
// command. Found the hard way: the first version asked only the hub, so
// installing an agent and asking whether it was serving got an answer about a
// different process.
func healthTargets(cfg config.Config) []target {
	var out []target

	if _, err := os.Stat(cfg.AgentDBPath()); err == nil {
		out = append(out, target{
			label: "agent",
			url: fmt.Sprintf("http://%s:%d/health",
				reachable(cfg.Agent.Bind), cfg.Agent.DashboardPort),
		})
	}
	if runsHub(cfg) {
		scheme := "http"
		if cfg.Hub.TLSEnabled() {
			scheme = "https"
		}
		out = append(out, target{
			label: "hub",
			url: fmt.Sprintf("%s://%s:%d/health",
				scheme, reachable(cfg.Hub.Bind), cfg.Hub.Port),
			tls: cfg.Hub.TLSEnabled(),
		})
	}

	// A machine with neither database has never run either daemon. Ask the
	// agent anyway so the answer is "nothing is listening" rather than nothing
	// at all.
	if len(out) == 0 {
		out = append(out, target{
			label: "agent",
			url: fmt.Sprintf("http://%s:%d/health",
				reachable(cfg.Agent.Bind), cfg.Agent.DashboardPort),
		})
	}
	return out
}

// reachable turns a bind address into one that can be connected to.
//
// A daemon bound to a specific LAN address is not on loopback, and asking
// 127.0.0.1 gets connection-refused from a process that is serving perfectly —
// this machine's hub binds 192.168.0.198 and was reported dead by exactly that
// mistake. The wildcards are the only ones that need translating.
func reachable(bind string) string {
	switch bind {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	default:
		return bind
	}
}
