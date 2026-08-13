package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
)

// ParsePURL is the inverse of PURL: it reads a package identifier back into the
// ecosystem and name advisories are filed under.
//
// It lives beside PURL rather than beside `pkgwatch check`, its first caller,
// because the round trip has to hold. A finding is stored as a purl and nothing
// else, so anything that wants to look up what fixes it — the CLI, and now the
// hub, which has no inventory of its own to join against — has to get back the
// same (ecosystem, name) pair the collector started from. Two spellings of that
// reversal means one of them silently finds no advisories.
func ParsePURL(raw string) (Package, error) {
	parsed, err := packageurl.FromString(raw)
	if err != nil {
		return Package{}, fmt.Errorf("not a valid purl: %w", err)
	}
	if parsed.Version == "" {
		return Package{}, fmt.Errorf("purl has no version: %s", raw)
	}

	ecosystem, err := ecosystemFromPURL(parsed)
	if err != nil {
		return Package{}, err
	}

	// npm scoped packages arrive split: namespace "@ctrl", name "tinycolor".
	// Distro purls put the distribution there instead (pkg:deb/debian/openssl),
	// which is not part of the package name.
	name := parsed.Name
	if parsed.Namespace != "" && (parsed.Type == "npm" || parsed.Type == "golang" || parsed.Type == "maven") {
		name = parsed.Namespace + "/" + parsed.Name
	}

	return Package{Ecosystem: ecosystem, Name: name, Version: parsed.Version}, nil
}

// purlTypeToEcosystem maps package-URL types onto OSV ecosystem names.
var purlTypeToEcosystem = map[string]string{
	"npm":    EcosystemNPM,
	"pypi":   EcosystemPyPI,
	"golang": EcosystemGo,
	"cargo":  EcosystemCrates,
	"apk":    EcosystemAlpine,
}

// ecosystemFromPURL resolves the OSV ecosystem, including the release qualifier
// that distribution advisories are filed against.
//
// A Debian 11 advisory and a Debian 12 advisory for the same package carry
// different fixed versions, so the release is not optional — checking without
// it would compare against another distribution's bounds.
func ecosystemFromPURL(parsed packageurl.PackageURL) (string, error) {
	qualifiers := parsed.Qualifiers.Map()

	if parsed.Type == "deb" {
		distro := qualifiers["distro"]
		if distro == "" {
			return "", fmt.Errorf("deb purls need a distro qualifier naming the release, " +
				"e.g. pkg:deb/debian/openssl@3.0.11-1?distro=debian-12 — advisories are release-specific")
		}
		return debEcosystem(parsed.Namespace, distro)
	}

	ecosystem, ok := purlTypeToEcosystem[strings.ToLower(parsed.Type)]
	if !ok {
		supported := SupportedEcosystems()
		sort.Strings(supported)
		return "", fmt.Errorf("purl type %q is not matched yet; supported ecosystems: %s",
			parsed.Type, strings.Join(supported, ", "))
	}
	if parsed.Type == "apk" {
		if release := qualifiers["distro"]; release != "" {
			return EcosystemAlpine + ":" + release, nil
		}
	}
	return ecosystem, nil
}

// debEcosystem turns a purl namespace and distro qualifier into the ecosystem
// string OSV files Debian and Ubuntu advisories under.
func debEcosystem(namespace, distro string) (string, error) {
	base := EcosystemDebian
	if strings.EqualFold(namespace, "ubuntu") {
		base = EcosystemUbuntu
	}

	// "debian-12" and "ubuntu-22.04" are the conventional spellings; OSV wants
	// just the release.
	release := distro
	if _, after, found := strings.Cut(distro, "-"); found {
		release = after
	}
	if release == "" {
		return "", fmt.Errorf("distro qualifier %q names no release", distro)
	}
	return base + ":" + release, nil
}
