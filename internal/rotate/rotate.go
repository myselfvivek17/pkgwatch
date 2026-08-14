// Package rotate builds the credential checklist for a machine that ran
// malicious code.
//
// The rule the whole package exists for: list only credentials that are
// actually on this machine. A generic checklist reads as a form to be filled
// in, and the one thing a person needs at that moment is the shortest true list
// — an AWS key that is not on this box is not an item to skip, it is an item
// that should never have been printed.
package rotate

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Categories, ordered by blast radius. Cloud keys can spend money and reach
// every other system; an application secret usually reaches one.
const (
	CategoryCloud    = "cloud"
	CategoryVCS      = "source control"
	CategoryRegistry = "package registry"
	CategorySSH      = "ssh"
	CategoryApp      = "application"
)

var categoryRank = map[string]int{
	CategoryCloud:    0,
	CategoryVCS:      1,
	CategoryRegistry: 2,
	CategorySSH:      3,
	CategoryApp:      4,
}

// Item is one credential worth rotating, found on this machine.
type Item struct {
	// ID is stable across runs, because a tick against it is stored.
	ID       string
	Label    string
	Category string

	// Path is where it was found. Named in full: "rotate your AWS key" is
	// advice, and "this file, on this machine, at this path" is a task.
	Path string

	// RotateURL is where the rotation is actually performed.
	RotateURL string

	// Why says what an attacker gets from this file, in one line.
	Why string
}

// candidate is a credential we know how to look for.
type candidate struct {
	id       string
	label    string
	category string

	// paths are relative to the home directory unless absolute.
	paths []string

	// contains, when set, is a marker the file must hold. An .npmrc with no
	// auth token is a registry preference, not a credential, and listing it
	// would pad the checklist with something nobody needs to rotate.
	contains  string
	rotateURL string
	why       string
}

var candidates = []candidate{
	{
		id: "aws", label: "AWS access keys", category: CategoryCloud,
		paths:     []string{".aws/credentials"},
		rotateURL: "https://console.aws.amazon.com/iam/home#/security_credentials",
		why:       "long-lived keys, usually with no expiry and broad permissions",
	},
	{
		id: "gcloud", label: "Google Cloud credentials", category: CategoryCloud,
		paths: []string{
			".config/gcloud/credentials.db",
			".config/gcloud/application_default_credentials.json",
			"AppData/Roaming/gcloud/credentials.db",
		},
		rotateURL: "https://console.cloud.google.com/apis/credentials",
		why:       "refresh tokens for your account and any service accounts you have impersonated",
	},
	{
		id: "azure", label: "Azure CLI tokens", category: CategoryCloud,
		paths:     []string{".azure/accessTokens.json", ".azure/msal_token_cache.json"},
		rotateURL: "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade",
		why:       "cached access and refresh tokens for the signed-in account",
	},
	{
		id: "github-cli", label: "GitHub CLI token", category: CategoryVCS,
		paths: []string{
			".config/gh/hosts.yml",
			"AppData/Roaming/GitHub CLI/hosts.yml",
		},
		rotateURL: "https://github.com/settings/tokens",
		why:       "a token that can push to every repository you can push to",
	},
	{
		id: "git-credentials", label: "Git stored credentials", category: CategoryVCS,
		paths:     []string{".git-credentials"},
		rotateURL: "https://github.com/settings/tokens",
		why:       "passwords and tokens in plain text, one per line",
	},
	{
		id: "npm", label: "npm auth token", category: CategoryRegistry,
		paths:     []string{".npmrc"},
		contains:  "_authToken",
		rotateURL: "https://www.npmjs.com/settings/~/tokens",
		why:       "publish rights to your packages — the way one compromise becomes several",
	},
	{
		id: "pypi", label: "PyPI upload token", category: CategoryRegistry,
		paths:     []string{".pypirc"},
		rotateURL: "https://pypi.org/manage/account/token/",
		why:       "publish rights to your projects",
	},
	{
		id: "docker", label: "Docker registry logins", category: CategoryRegistry,
		paths:     []string{".docker/config.json"},
		contains:  "auth",
		rotateURL: "https://hub.docker.com/settings/security",
		why:       "push access to your images",
	},
	{
		id: "cargo", label: "crates.io token", category: CategoryRegistry,
		paths:     []string{".cargo/credentials.toml", ".cargo/credentials"},
		rotateURL: "https://crates.io/settings/tokens",
		why:       "publish rights to your crates",
	},
	{
		id: "ssh", label: "SSH private keys", category: CategorySSH,
		paths: []string{
			".ssh/id_ed25519", ".ssh/id_rsa", ".ssh/id_ecdsa", ".ssh/id_dsa",
		},
		rotateURL: "https://github.com/settings/keys",
		why:       "shell access to every host that trusts them; a passphrase only slows this down",
	},
	{
		id: "kube", label: "Kubernetes config", category: CategoryApp,
		paths:     []string{".kube/config"},
		rotateURL: "",
		why:       "cluster credentials, often with no expiry",
	},
	{
		id: "netrc", label: "netrc logins", category: CategoryApp,
		paths:     []string{".netrc", "_netrc"},
		rotateURL: "",
		why:       "passwords in plain text for whatever hosts are listed in it",
	},
}

// Detect returns the credentials that exist under home, worst blast radius
// first.
//
// Existence is the filter. Everything this returns is a real file on this
// machine that a process running as this user could have read, which is what
// makes the list short enough to work through while it still matters.
func Detect(home string) []Item {
	var items []Item

	for _, c := range candidates {
		for _, rel := range c.paths {
			path := rel
			if !filepath.IsAbs(path) {
				path = filepath.Join(home, filepath.FromSlash(rel))
			}
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			if c.contains != "" && !fileContains(path, c.contains) {
				continue
			}

			items = append(items, Item{
				ID: c.id, Label: c.label, Category: c.category,
				Path: path, RotateURL: c.rotateURL, Why: c.why,
			})
			break // one entry per credential kind, at the first path that exists
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		return categoryRank[items[i].Category] < categoryRank[items[j].Category]
	})
	return items
}

// Describe names a credential from its stored ID alone, without looking at any
// filesystem.
//
// The hub needs this: it holds ticks replicated from machines whose home
// directories it cannot see, and rendering a bare "github-cli" would make the
// page a lookup table. An unknown ID is returned as itself rather than dropped —
// a tick against a credential this build no longer knows about is still work
// somebody did, and silently omitting it would shorten the checklist.
func Describe(id string) Item {
	for _, c := range candidates {
		if c.id == id {
			return Item{ID: c.id, Label: c.label, Category: c.category,
				RotateURL: c.rotateURL, Why: c.why}
		}
	}
	return Item{ID: id, Label: id, Category: "unknown",
		Why: "recorded by an agent that knows this credential and this build does not"}
}

// fileContains reports whether a marker appears in a small config file.
//
// Capped rather than streamed: these are configuration files of a few
// kilobytes, and a credential store that has grown to a gigabyte is not
// something to read into memory looking for a substring.
func fileContains(path, marker string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 64<<10)
	n, _ := file.Read(buf)
	return strings.Contains(string(buf[:n]), marker)
}

// Home is the user's home directory, or "" if it cannot be determined.
//
// Nothing here falls back to a guess. A checklist built against the wrong home
// directory finds nothing and reports a clean machine, which is the worst
// available answer.
func Home() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	if runtime.GOOS == "windows" {
		return os.Getenv("USERPROFILE")
	}
	return os.Getenv("HOME")
}
