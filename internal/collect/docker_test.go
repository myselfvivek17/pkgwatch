package collect

import (
	"testing"
)

// dpkg status is an RFC 822-ish file, and the records for packages that were
// removed but left their configuration behind sit right alongside the installed
// ones. Counting those would report software that is not on the disk.
func TestParseDpkgStatus(t *testing.T) {
	raw := []byte(`Package: openssl
Status: install ok installed
Priority: optional
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit

Package: removed-but-configured
Status: deinstall ok config-files
Version: 1.0-1

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1
`)

	got := parseDpkgStatus(raw)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2 installed: %+v", len(got), got)
	}
	if got[0].name != "openssl" || got[0].version != "3.0.11-1~deb12u2" {
		t.Errorf("first = %+v", got[0])
	}
	// Epochs have to survive intact — they are the leading component of a dpkg
	// version comparison.
	if got[1].version != "1:1.2.13.dfsg-1" {
		t.Errorf("epoch was lost: %+v", got[1])
	}
}

func TestParseAPKInstalled(t *testing.T) {
	raw := []byte(`C:Q1eVpkavKKarM1sjrTLBg8Uk0PoY0=
P:musl
V:1.2.4_git20230717-r4
A:x86_64

C:Q1abcdef
P:busybox
V:1.36.1-r15
A:x86_64
`)

	got := parseAPKInstalled(raw)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(got), got)
	}
	if got[0].name != "musl" || got[0].version != "1.2.4_git20230717-r4" {
		t.Errorf("first = %+v", got[0])
	}
}

// The release qualifier is not decoration: the same CVE carries a different
// fixed version in each distribution release, so matching without it compares
// against the wrong bounds.
func TestEcosystemFromOSRelease(t *testing.T) {
	cases := []struct {
		name            string
		raw             string
		ecosystem, path string
	}{
		{
			name:      "debian",
			raw:       "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n",
			ecosystem: "Debian:13", path: "/var/lib/dpkg/status",
		},
		{
			// OSV files long-term releases with an :LTS suffix. Producing
			// "Ubuntu:24.04" instead is not a near miss — the lookup returns zero
			// rows, and on a host that is 1,800 packages reading as nothing on
			// file, which is indistinguishable from a clean machine.
			name: "ubuntu LTS",
			raw: "ID=ubuntu\nVERSION_ID=\"24.04\"\n" +
				"VERSION=\"24.04.3 LTS (Noble Numbat)\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n",
			ecosystem: "Ubuntu:24.04:LTS", path: "/var/lib/dpkg/status",
		},
		{
			name:      "ubuntu interim release carries no suffix",
			raw:       "ID=ubuntu\nVERSION_ID=\"25.10\"\nVERSION=\"25.10 (Questing Quokka)\"\n",
			ecosystem: "Ubuntu:25.10", path: "/var/lib/dpkg/status",
		},
		{
			// OSV files Alpine advisories per minor release, not per patch.
			name:      "alpine patch level is dropped",
			raw:       "ID=alpine\nVERSION_ID=3.19.1\n",
			ecosystem: "Alpine:v3.19", path: "/lib/apk/db/installed",
		},
		{
			name: "distroless has no distribution packages",
			raw:  "ID=something-else\nVERSION_ID=1\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ecosystem, path := ecosystemFromOSRelease([]byte(tc.raw))
			if ecosystem != tc.ecosystem || path != tc.path {
				t.Errorf("got (%q, %q), want (%q, %q)", ecosystem, path, tc.ecosystem, tc.path)
			}
		})
	}
}

// Exercises the real engine when one is running. Skipped otherwise, so CI and
// machines without Docker stay green — but on a machine that has it, this is
// the only thing that proves the transport works at all.
func TestAgainstRealDocker(t *testing.T) {
	client, ok := DialDocker()
	if !ok {
		t.Skip("no docker endpoint configured")
	}

	containers, err := client.Containers()
	if err != nil {
		if absent(err) {
			t.Skip("docker is not running")
		}
		t.Fatalf("list containers: %v", err)
	}
	t.Logf("docker reports %d running container(s)", len(containers))
	if len(containers) == 0 {
		t.Skip("no running containers to read")
	}

	read := 0
	for _, container := range containers {
		t.Logf("container %s image=%q state=%q", container.short(), container.Image, container.State)

		release, err := client.File(container.ID, "/etc/os-release")
		t.Logf("  os-release: %d bytes, err=%v", len(release), err)
		if len(release) > 0 {
			ecosystem, path := ecosystemFromOSRelease(release)
			t.Logf("  ecosystem=%q dbPath=%q", ecosystem, path)
		}

		packages, err := client.packages(container)
		if err != nil {
			t.Errorf("read %s: %v", container.short(), err)
			continue
		}
		t.Logf("  -> %d distribution package(s)", len(packages))
		if len(packages) > 0 {
			t.Logf("  -> first: %s %s (%s) at %q",
				packages[0].Name, packages[0].Version, packages[0].Ecosystem, packages[0].InstallDir)
			read++
		}
	}
	if read == 0 {
		t.Error("no container yielded any packages; a Debian or Alpine container should")
	}
}
