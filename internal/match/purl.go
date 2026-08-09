package match

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

// PURL renders a package as the identifier findings, decisions and inventory
// rows are all keyed by.
//
// It lives here rather than beside its first caller because every part of
// pkgwatch that names a package has to spell it the same way — the gate records
// a decision, the collector records an installation, and the watcher joins the
// two. A second spelling anywhere means findings that never match anything.
func PURL(ecosystem, name, version string) string {
	instance := packageurl.PackageURL{Version: version}
	switch BaseEcosystem(ecosystem) {
	case EcosystemNPM:
		instance.Type = packageurl.TypeNPM
		// npm scopes are the purl namespace: @ctrl/tinycolor is namespace "@ctrl".
		if scope, bare, found := strings.Cut(strings.TrimPrefix(name, "@"), "/"); found {
			instance.Namespace = "@" + scope
			instance.Name = bare
		} else {
			instance.Name = name
		}
	case EcosystemPyPI:
		instance.Type = packageurl.TypePyPi
		instance.Name = NormalizeName(ecosystem, name)

	case EcosystemGo:
		instance.Type = packageurl.TypeGolang
		if namespace, bare, found := cutLast(name, "/"); found {
			instance.Namespace = namespace
			instance.Name = bare
		} else {
			instance.Name = name
		}
	case EcosystemCrates:
		instance.Type = "cargo"
		instance.Name = name

	// Distribution packages carry their release, and it is not decoration: the
	// same CVE has a different fixed version in Debian 11 and Debian 12, so a
	// purl without the release names a package whose advisories cannot be looked
	// up. This is also the spelling `pkgwatch check` parses back, and the two
	// have to agree or a finding recorded by the collector would never match a
	// package named by hand.
	case EcosystemDebian, EcosystemUbuntu:
		instance.Type = "deb"
		instance.Namespace = strings.ToLower(BaseEcosystem(ecosystem))
		instance.Name = name
		if release := releaseOf(ecosystem); release != "" {
			instance.Qualifiers = packageurl.QualifiersFromMap(map[string]string{
				"distro": instance.Namespace + "-" + release,
			})
		}
	case EcosystemAlpine:
		instance.Type = "apk"
		instance.Namespace = "alpine"
		instance.Name = name
		if release := releaseOf(ecosystem); release != "" {
			instance.Qualifiers = packageurl.QualifiersFromMap(map[string]string{"distro": release})
		}

	default:
		instance.Type = strings.ToLower(BaseEcosystem(ecosystem))
		instance.Name = name
	}
	return instance.ToString()
}

// releaseOf returns the qualifier OSV appends to a distribution ecosystem —
// "12" from "Debian:12", "v3.19" from "Alpine:v3.19".
func releaseOf(ecosystem string) string {
	_, release, _ := strings.Cut(ecosystem, ":")
	return release
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// PURLBase is the package identifier with no version — what an override that
// covers a whole package for one install is recorded against.
func PURLBase(ecosystem, name string) string { return PURL(ecosystem, name, "") }
