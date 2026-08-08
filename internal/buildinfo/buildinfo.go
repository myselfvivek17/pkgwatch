// Package buildinfo carries values stamped in at link time.
package buildinfo

// Overridden via -ldflags "-X github.com/myselfvivek17/pkgwatch/internal/buildinfo.Version=..."
var (
	Version = "dev"
	Commit  = "none"
)
