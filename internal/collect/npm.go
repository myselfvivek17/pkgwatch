package collect

import (
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// packageJSON is the part of a package.json the inventory needs.
type packageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// lifecycleScripts run automatically on install, with the privileges of whoever
// typed the command. They are the mechanism nearly every npm supply-chain
// attack actually uses, so whether a package has one is worth recording — it
// multiplies a finding's score (§5.2) and decides whether credentials need
// rotating.
var lifecycleScripts = []string{"preinstall", "install", "postinstall"}

// NPM walks a node_modules tree and reports what is installed in it.
//
// Nested node_modules are walked too: npm hoists what it can, but a version
// conflict leaves a dependency nested under its parent, and that copy is just
// as installed as any other.
func NPM(nodeModules, scope string, known Known) Result {
	var out Result

	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("collect: cannot read node_modules", "path", nodeModules, "error", err)
			out.Skipped++
		}
		return out
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case name == ".bin" || name == ".package-lock.json":
			continue
		case strings.HasPrefix(name, "@"):
			// A scope directory holds packages, not a package.
			scoped, err := os.ReadDir(filepath.Join(nodeModules, name))
			if err != nil {
				out.Skipped++
				continue
			}
			for _, inner := range scoped {
				if inner.IsDir() {
					out.Merge(npmPackage(filepath.Join(nodeModules, name, inner.Name()), scope, known))
				}
			}
		default:
			out.Merge(npmPackage(filepath.Join(nodeModules, name), scope, known))
		}
	}
	return out
}

// npmPackage reads one package directory, and recurses into its own
// node_modules if it has one.
func npmPackage(dir, scope string, known Known) Result {
	var out Result

	mtime := dirMTime(dir)
	if known.unchanged(dir, mtime) {
		out.Unchanged++
	} else {
		raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			// Not every directory under node_modules is a package: npm leaves
			// caches and staging directories behind. Only count a miss when
			// something is there but unreadable.
			if !os.IsNotExist(err) {
				out.Skipped++
			}
		} else {
			var manifest packageJSON
			if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Name == "" || manifest.Version == "" {
				out.Skipped++
			} else {
				out.add(Package{
					Ecosystem:  match.EcosystemNPM,
					Name:       manifest.Name,
					Version:    manifest.Version,
					Scope:      scope,
					InstallDir: dir,
					HasScripts: hasLifecycleScript(manifest.Scripts),
					DirMTime:   mtime,
				})
			}
		}
	}

	if nested := filepath.Join(dir, "node_modules"); isDir(nested) {
		out.Merge(NPM(nested, scope, known))
	}
	return out
}

func hasLifecycleScript(scripts map[string]string) bool {
	for _, name := range lifecycleScripts {
		if strings.TrimSpace(scripts[name]) != "" {
			return true
		}
	}
	return false
}

// NPMGlobalRoot locates the global node_modules.
//
// `npm root -g` is asked first because it is the only answer that is right on a
// machine using nvm, volta, fnm or a prefix override — all of which move the
// global root somewhere no convention predicts. The conventional paths are a
// fallback for when npm is absent or slow to answer.
func NPMGlobalRoot() string {
	if out, err := exec.Command("npm", "root", "-g").Output(); err == nil {
		if root := strings.TrimSpace(string(out)); isDir(root) {
			return root
		}
	}

	for _, candidate := range conventionalNPMRoots() {
		if isDir(candidate) {
			slog.Debug("collect: using conventional npm global root", "path", candidate)
			return candidate
		}
	}
	return ""
}

func conventionalNPMRoots() []string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return []string{filepath.Join(appData, "npm", "node_modules")}
		}
		return nil
	}

	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".npm-global", "lib", "node_modules"))
	}
	return append(roots,
		"/usr/local/lib/node_modules",
		"/usr/lib/node_modules",
		"/opt/homebrew/lib/node_modules",
	)
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
