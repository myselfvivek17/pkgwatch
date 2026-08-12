module github.com/myselfvivek17/pkgwatch

// Raised to 1.25 by golang.org/x/sys, not by anything in this codebase, which
// targets the spec's 1.23+. Do not stamp this from whatever toolchain happens
// to run `go mod tidy` — CI reads this value, and a module pinned above what
// the toolchain provides breaks govulncheck before it can load a single package.
go 1.25.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/Masterminds/semver/v3 v3.5.0
	github.com/go-chi/chi/v5 v5.3.1
	github.com/package-url/packageurl-go v0.1.6
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.55.0
	modernc.org/sqlite v1.56.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
