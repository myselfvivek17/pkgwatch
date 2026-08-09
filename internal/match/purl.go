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
	default:
		instance.Type = strings.ToLower(BaseEcosystem(ecosystem))
		instance.Name = name
	}
	return instance.ToString()
}

// PURLBase is the package identifier with no version — what an override that
// covers a whole package for one install is recorded against.
func PURLBase(ecosystem, name string) string { return PURL(ecosystem, name, "") }
