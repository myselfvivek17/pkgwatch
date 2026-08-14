// Package scriptguard turns npm's install scripts off globally and back on for
// named packages.
//
// A lifecycle script is arbitrary code running as you, at install time, before
// any advisory has had a chance to describe it. It is the mechanism nearly
// every npm supply-chain attack of the last five years actually used, and npm
// runs them by default.
//
// Unlike the gate, this is deliberately persistent. The gate configures itself
// through the environment so nothing is left behind if the wrapper dies, which
// is right for a proxy that should apply to one invocation. A script guard that
// only worked when you remembered to type `pkgwatch npm` would not be a guard —
// the install that hurts you is the one you ran normally. So this edits the
// user's npm config, and every operation says exactly what it changed and how
// to undo it.
package scriptguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Ecosystem is the only one this covers, and the package says so rather than
// pretending to be general.
//
// pip has no equivalent switch: a source distribution's setup.py *is* the
// install, so there is nothing to turn off short of refusing source
// distributions entirely (`--only-binary=:all:`), which is a different feature
// with a different cost.
const Ecosystem = "npm"

// ErrNoNPM means npm is not on PATH, so there is nothing to configure.
var ErrNoNPM = errors.New("npm is not installed or not on PATH")

// State is what npm currently thinks.
type State struct {
	// Enabled is the effective setting, which is what actually decides whether
	// scripts run. It can be true because of a project .npmrc or an environment
	// variable rather than because of anything this tool did.
	Enabled bool

	// SetByUserConfig is whether the user-level config carries it. The two
	// differ when something else set it, and telling them apart is the
	// difference between "the guard is on" and "something is currently making
	// it look on".
	SetByUserConfig bool

	// UserConfig is the file the user-level setting lives in.
	UserConfig string
}

// Status reports what npm is currently configured to do.
func Status() (State, error) {
	if _, err := exec.LookPath("npm"); err != nil {
		return State{}, ErrNoNPM
	}

	effective, err := get("ignore-scripts")
	if err != nil {
		return State{}, err
	}
	userConfig, err := get("userconfig")
	if err != nil {
		return State{}, err
	}
	// --location=user reads only the user file, so this distinguishes "the user
	// config sets it" from "something else in the chain does".
	atUser, err := getAt("ignore-scripts", "user")
	if err != nil {
		return State{}, err
	}

	return State{
		Enabled:         effective == "true",
		SetByUserConfig: atUser == "true",
		UserConfig:      userConfig,
	}, nil
}

// Enable turns install scripts off for every npm invocation by this user.
func Enable() error { return set("ignore-scripts", "true") }

// Disable removes the setting from the user config.
//
// Deleted rather than set to false, so npm goes back to whatever it would have
// done on its own. Writing false would look identical while quietly overriding
// a project or organisation config that wanted it on.
func Disable() error {
	if _, err := exec.LookPath("npm"); err != nil {
		return ErrNoNPM
	}
	out, err := exec.Command("npm", "config", "delete", "ignore-scripts", "--location=user").
		CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm config delete: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RunTimeout bounds a rebuild.
//
// The command being run is a package's install script — the arbitrary code this
// whole package exists to keep switched off. Running it with no deadline means
// one that waits on input, or on a network that never answers, hangs the
// command that authorised it with no way back except a kill.
const RunTimeout = 5 * time.Minute

// ErrBadPackageName means the argument is not something npm should be handed.
var ErrBadPackageName = errors.New("not a valid npm package name")

// npmName matches what npm accepts: an optional @scope/ prefix, then lowercase
// name characters. Deliberately strict — this string is about to become a
// command-line argument to a program that runs code.
var npmName = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// Run executes one package's install scripts despite the guard.
//
// `npm rebuild <name> --ignore-scripts=false` is the whole mechanism: npm has
// no per-package allowlist of its own, so an allowance is the guard staying on
// everywhere and this one package being built by hand. Verified against npm
// 11: with ignore-scripts set, a plain rebuild runs nothing, and this flag
// overrides it for the one invocation.
//
// The name is validated and passed after `--`. Without both, a package called
// `--foo` is a flag rather than a package: the one function in this codebase
// that deliberately executes third-party code is the last place to pass an
// unchecked string through to a command line.
func Run(ctx context.Context, dir, name string) (string, error) {
	if !npmName.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrBadPackageName, name)
	}
	if _, err := exec.LookPath("npm"); err != nil {
		return "", ErrNoNPM
	}

	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "rebuild", "--ignore-scripts=false", "--", name)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf(
			"npm rebuild %s gave up after %s — an install script that does not finish is "+
				"exactly what the guard is for", name, RunTimeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("npm rebuild %s: %w", name, err)
	}
	return string(out), nil
}

func get(key string) (string, error) { return getAt(key, "") }

func getAt(key, location string) (string, error) {
	args := []string{"config", "get", key}
	if location != "" {
		args = append(args, "--location="+location)
	}
	out, err := exec.Command("npm", args...).Output()
	if err != nil {
		return "", fmt.Errorf("npm config get %s: %w", key, err)
	}
	// npm prints "undefined" for a key the requested location does not set.
	value := strings.TrimSpace(string(out))
	if value == "undefined" || value == "null" {
		return "", nil
	}
	return value, nil
}

func set(key, value string) error {
	if _, err := exec.LookPath("npm"); err != nil {
		return ErrNoNPM
	}
	out, err := exec.Command("npm", "config", "set", key, value, "--location=user").
		CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm config set %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}
