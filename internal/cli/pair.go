package cli

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/myselfvivek17/pkgwatch/internal/agent"
	"github.com/myselfvivek17/pkgwatch/internal/buildinfo"
	"github.com/myselfvivek17/pkgwatch/internal/config"
	"github.com/myselfvivek17/pkgwatch/internal/device"
	"github.com/myselfvivek17/pkgwatch/internal/fleet"
	"github.com/myselfvivek17/pkgwatch/internal/hub"
	"github.com/myselfvivek17/pkgwatch/internal/repo"
	"github.com/myselfvivek17/pkgwatch/internal/secret"
)

// --- agent side -------------------------------------------------------------

func pairCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pair",
		Short: "Pair this agent with a hub",
		Long: "Exchanges a pairing code for a device token.\n\n" +
			"The device ID printed at the end is derived from this machine's key. Compare it\n" +
			"with the ID shown on the hub before approving — that comparison is what stops\n" +
			"something in the middle pairing itself in this machine's place.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hubURL, _ := cmd.Flags().GetString("hub")
			code, _ := cmd.Flags().GetString("code")
			if hubURL == "" || code == "" {
				return errors.New("both --hub and --code are required; get a code with `pkgwatch hub pair-code` on the hub")
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			if st.Paired {
				return fmt.Errorf("this agent is already paired with %s — run `pkgwatch agent unpair` first", orDash(st.HubURL))
			}

			// A fresh key per pairing, so the device ID a person is about to
			// compare belongs to this pairing and not to some earlier one.
			id, err := device.Generate()
			if err != nil {
				return err
			}

			client := &fleet.Client{BaseURL: hubURL, Identity: id}
			resp, err := client.Enroll(fleet.EnrollRequest{
				DeviceID:  id.ID(),
				PublicKey: device.EncodePublic(id.Public),
				Code:      code,
				Hostname:  st.Hostname,
				OS:        runtime.GOOS,
				Arch:      runtime.GOARCH,
				Version:   buildinfo.Version,
				SyncLevel: cfg.Agent.SyncLevel,
			})
			if err != nil {
				return err
			}

			for key, value := range map[string]string{
				repo.HubDeviceKey: id.Encode(),
				repo.HubDeviceID:  resp.DeviceID,
				repo.HubToken:     resp.Token,
				repo.HubURL:       strings.TrimRight(hubURL, "/"),
			} {
				if err := st.Repo.SetHubState(key, value); err != nil {
					return fmt.Errorf("store pairing: %w", err)
				}
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolled with %s.\n\n", hubURL)
			fmt.Fprintf(out, "  device ID   %s\n", resp.DeviceID)
			fmt.Fprintf(out, "  status      %s\n\n", resp.Status)
			fmt.Fprintf(out, "Approve it on the hub:\n\n    pkgwatch hub devices approve %s\n\n", resp.DeviceID)
			fmt.Fprintf(out, "Check that the ID above matches the one the hub lists before approving.\n")
			fmt.Fprintf(out, "Nothing syncs until it is approved. This agent gates installs either way.\n")
			return nil
		},
	}
	cmd.Flags().String("hub", "", "hub base URL, e.g. https://homelab:4875")
	cmd.Flags().String("code", "", "pairing code from `pkgwatch hub pair-code`")
	return cmd
}

func unpairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpair",
		Short: "Forget the paired hub",
		Long: "Removes the device key, token and hub URL from this machine.\n\n" +
			"Gating, inventory and the local dashboard are unaffected — the agent has\n" +
			"never depended on a hub.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			st, err := agent.Open(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			if !st.Paired {
				fmt.Fprintln(cmd.OutOrStdout(), "Not paired with anything.")
				return nil
			}
			if err := st.Repo.ClearHubState(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Forgotten %s. Revoke the device on the hub too — this end cannot.\n", orDash(st.HubURL))
			return nil
		},
	}
}

// --- hub side ---------------------------------------------------------------

func pairCodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pair-code",
		Short: "Generate a single-use pairing code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openHub(cmd)
			if err != nil {
				return err
			}
			defer st.Close()

			code, err := secret.PairCode()
			if err != nil {
				return err
			}
			if err := st.Repo.IssuePairCode(code, time.Now()); err != nil {
				return err
			}
			// Housekeeping while we are here — redemption already checks expiry,
			// so anything still sitting in the table is spent, not live.
			if _, err := st.Repo.ExpirePairCodes(time.Now()); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"\n    %s\n\nGood for %s, once. On the agent:\n\n    pkgwatch agent pair --hub <url> --code %s\n\n",
				code, repo.PairCodeTTL, code)
			return nil
		},
	}
}

func devicesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "devices", Short: "Manage paired devices"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List enrolled devices",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, err := openHub(cmd)
				if err != nil {
					return err
				}
				defer st.Close()

				devices, err := st.Repo.Devices()
				if err != nil {
					return err
				}
				if len(devices) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(),
						"No devices enrolled. Generate a code with `pkgwatch hub pair-code`.")
					return nil
				}

				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "DEVICE ID\tHOST\tOS/ARCH\tSTATUS\tLAST REPORT")
				for _, d := range devices {
					fmt.Fprintf(w, "%s\t%s\t%s/%s\t%s\t%s\n",
						d.ID, d.Hostname, d.OS, d.Arch, d.Status, lastReport(d))
				}
				return w.Flush()
			},
		},
		statusChangeCmd("approve", "Approve a pending device", repo.DeviceStatusApproved),
		statusChangeCmd("revoke", "Revoke a device's token", repo.DeviceStatusRevoked),
	)
	return cmd
}

// lastReport never renders "never reported" as a time.
//
// An approved machine that has never sent anything and one that stopped
// yesterday are different problems, and a dash where a timestamp goes is the
// only thing that says which is which.
func lastReport(d repo.Device) string {
	if !d.EverReported() {
		return "never"
	}
	return time.Since(d.LastSeen).Round(time.Minute).String() + " ago"
}

func statusChangeCmd(use, short, status string) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <device-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openHub(cmd)
			if err != nil {
				return err
			}
			defer st.Close()

			id := strings.ToUpper(args[0])
			existing, err := st.Repo.Device(id)
			if err != nil {
				return err
			}
			if err := st.Repo.SetDeviceStatus(id, status, time.Now()); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s (%s) is now %s.\n", id, existing.Hostname, status)
			if status == repo.DeviceStatusApproved {
				// Said out loud because the ID is the fingerprint. Approving
				// without checking it is approving whatever answered the code.
				fmt.Fprintln(out, "Check this ID matches the one printed on that machine's own `pkgwatch agent pair` output.")
			} else {
				fmt.Fprintln(out, "It will stop syncing. It keeps gating installs locally — that never depended on this hub.")
			}
			return nil
		},
	}
}

// openHub opens the hub database for a one-shot command.
func openHub(cmd *cobra.Command) (*hub.State, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return hub.Open(cfg)
}
