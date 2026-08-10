package collect

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	stdpath "path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// dockerTimeout bounds every engine call.
//
// Short on purpose. A wedged Docker must not dominate a scan the user is
// waiting on — the first version of this used thirty seconds and turned a
// 700ms scan into a 30s one when the pipe did not answer.
const dockerTimeout = 10 * time.Second

// Docker reads the distribution packages installed inside running containers.
//
// This is what makes distribution advisories usable at all. A base image name
// carries no version information — "debian:12" says nothing about which openssl
// is in it, and the same tag means different bytes on different days. The
// package database inside the container is the only thing that does.
//
// Nothing is executed inside the container. The Docker API can copy a path out
// as a tar stream, so the package list is read the same way a backup would read
// it: /var/lib/dpkg/status on Debian and Ubuntu, /lib/apk/db/installed on
// Alpine. A compromised container never gets to run anything on our behalf.
//
// Only running containers are read. Reading a stopped one means creating a
// throwaway container from its image, which mutates Docker state — a scan
// should not do that without being asked.
func Docker(known Known) Result {
	var out Result

	client, ok := DialDocker()
	if !ok {
		// No Docker on this machine is the common case, not a problem.
		return out
	}

	containers, err := client.Containers()
	if err != nil {
		if absent(err) {
			// No Docker on this machine. Common, and not a problem.
			return out
		}
		slog.Warn("collect: docker is present but would not list containers", "error", err)
		out.Skipped++
		return out
	}

	out.ContainersScanned = true

	for _, container := range containers {
		found, err := client.packages(container)
		if err != nil {
			// One unreadable container must not lose the others, and it is a gap
			// in coverage worth counting rather than swallowing.
			slog.Warn("collect: could not read container packages",
				"container", container.short(), "image", container.Image, "error", err)
			out.Skipped++
			continue
		}
		out.add(found...)
	}
	return out
}

// Container is the subset of Docker's container listing that matters here.
type Container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

func (c Container) short() string {
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

// label is what the dashboard shows to say which container a finding is in.
//
// It is also the install path rows are matched on, which is why the digest is
// stripped. Docker reports an image as repo:tag@sha256:… once it has been
// pulled by digest, and that digest changes on every image update — so keeping
// it would change the install path of a container that had not moved, retiring
// its entire package list and re-adding it under a new path. That is the same
// mistake as building identity out of an ecosystem string that can be revised:
// anything in a key has to be something that does not legitimately change.
func (c Container) label() string {
	name := c.short()
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	return "container:" + name + " (" + imageWithoutDigest(c.Image) + ")"
}

// imageWithoutDigest drops a pinned digest, keeping repo and tag.
func imageWithoutDigest(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		return image[:at]
	}
	return image
}

// DockerClient talks to the Docker engine over its local socket.
//
// Hand-rolled over stdlib rather than through the official SDK: the SDK is an
// enormous dependency tree and this needs three endpoints. The dependency
// budget for a tool that watches for supply-chain attacks is not somewhere to
// be relaxed.
//
// It does not use http.Transport either, and that is not stubbornness. The
// transport reads and writes a connection from two goroutines at once, which a
// Windows named pipe opened for synchronous I/O cannot do: the read blocks
// first and holds the handle, so the request is never written and the only
// symptom is a client timeout. One connection per request, written and read in
// order, sidesteps that entirely — and three requests per container is not a
// place where connection reuse matters.
type DockerClient struct {
	dial func() (net.Conn, error)
	host string
}

// DialDocker prepares a client. It does not connect: opening a named pipe just
// to find out whether Docker exists consumes one of the engine's few pipe
// instances, and the instance is not always free again by the time the real
// request dials — which surfaced as "all pipe instances are busy" on a machine
// where Docker was working perfectly. Absence is discovered on first use
// instead, where the error can be told apart from a real failure.
func DialDocker() (*DockerClient, bool) {
	network, address, host := dockerEndpoint()
	if address == "" {
		return nil, false
	}

	if network == "tcp" {
		return &DockerClient{
			dial: func() (net.Conn, error) { return net.DialTimeout("tcp", address, dockerTimeout) },
			host: host,
		}, true
	}
	return &DockerClient{
		dial: func() (net.Conn, error) { return dialLocal(context.Background(), network, address) },
		// The host in the URL is ignored by a unix socket or a named pipe, but
		// an HTTP request has to name one.
		host: "http://docker",
	}, true
}

// dockerEndpoint resolves where the engine is listening.
func dockerEndpoint() (network, address, host string) {
	if fromEnv := os.Getenv("DOCKER_HOST"); fromEnv != "" {
		parsed, err := url.Parse(fromEnv)
		if err != nil {
			slog.Warn("collect: DOCKER_HOST is not a URL, ignoring", "value", fromEnv)
			return "", "", ""
		}
		switch parsed.Scheme {
		case "unix":
			return "unix", parsed.Path, "http://docker"
		case "npipe":
			return "npipe", strings.ReplaceAll(parsed.Path, "/", `\`), "http://docker"
		case "tcp", "http":
			return "tcp", parsed.Host, "http://" + parsed.Host
		}
		return "", "", ""
	}

	if runtime.GOOS == "windows" {
		return "npipe", `\\.\pipe\docker_engine`, "http://docker"
	}
	return "unix", "/var/run/docker.sock", "http://docker"
}

// absent reports whether an error means Docker simply is not installed here,
// as opposed to being installed and unwell.
//
// The difference matters: no Docker is the common case and deserves silence,
// while a Docker that is present and refusing to answer is a gap in coverage
// and has to be said out loud.
func absent(err error) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return true
	}
	// Windows reports a missing pipe as "The system cannot find the file
	// specified", which does not always arrive as ErrNotExist through the
	// layers above.
	return strings.Contains(err.Error(), "cannot find the file")
}

// get performs one Docker API request on its own connection.
//
// The response body owns the connection and closes it, so every caller must
// close the body — the same contract net/http has.
func (c *DockerClient) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "close")

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}

	// A watchdog rather than a socket deadline. Deadlines are unavailable on a
	// synchronous named pipe, and without something here a wedged engine would
	// hang a scan the user is waiting on. Closing the connection is what
	// unblocks a read that is already in progress.
	timer := time.AfterFunc(dockerTimeout, func() { conn.Close() })

	if err := req.Write(conn); err != nil {
		timer.Stop()
		conn.Close()
		return nil, fmt.Errorf("docker: send request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		timer.Stop()
		conn.Close()
		return nil, fmt.Errorf("docker: read response: %w", err)
	}

	resp.Body = connBody{ReadCloser: resp.Body, conn: conn, timer: timer}
	return resp, nil
}

// connBody ties the response body's lifetime to the connection it came from.
type connBody struct {
	io.ReadCloser
	conn  net.Conn
	timer *time.Timer
}

func (b connBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	if closeErr := b.conn.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Containers lists every container that exists, running or not.
//
// all=1 matters. Docker's default lists only running containers, and a
// container that exists but is stopped still has its filesystem on disk with
// every vulnerable package in it. Listing only running ones meant a stopped
// container's rows stopped being seen, so they were retired, so every finding
// against them closed — on a real machine two stopped immich containers took
// 322 packages and their advisories with them, silently. Stopping a container
// is not patching it; starting it again brings the CVEs back.
//
// This costs nothing: the archive endpoint reads a stopped container's files
// without starting it, exactly as it does a running one. That is why the plan
// puts non-running *images* behind a flag — those need a container created
// first, which mutates Docker state — while containers that already exist need
// no such thing.
func (c *DockerClient) Containers() ([]Container, error) {
	resp, err := c.get("/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: /containers/json returned %s", resp.Status)
	}

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("docker: decode container list: %w", err)
	}
	return containers, nil
}

// errNotInContainer means the path does not exist inside the container.
var errNotInContainer = errors.New("path not present in container")

// File copies one path out of a container, following symlinks.
//
// Docker returns the path as a tar stream, which is the whole point: the file
// is read out, not read by anything running inside.
//
// Symlinks have to be followed by hand because the archive endpoint copies the
// path exactly as given — asking for a link yields a tar entry with a target
// and no content. That is not an edge case: /etc/os-release is a symlink into
// /usr/lib on Debian, so the very first thing this reads is one, and treating
// it as missing made every container look like it had no distribution at all.
func (c *DockerClient) File(containerID, filePath string) ([]byte, error) {
	// Bounded, because a container can contain a symlink loop and this is
	// following links chosen by whatever built the image.
	for hop := 0; hop < 8; hop++ {
		data, target, err := c.archive(containerID, filePath)
		if err != nil {
			return nil, err
		}
		if target == "" {
			return data, nil
		}
		filePath = resolveContainerLink(filePath, target)
	}
	return nil, fmt.Errorf("docker: too many symlinks resolving %s", filePath)
}

// archive fetches one path. A symlink comes back as an empty body and the link
// target.
func (c *DockerClient) archive(containerID, filePath string) (data []byte, linkTarget string, err error) {
	resp, err := c.get("/containers/" + containerID + "/archive?path=" + url.QueryEscape(filePath))
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", errNotInContainer
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("docker: archive %s returned %s", filePath, resp.Status)
	}

	reader := tar.NewReader(resp.Body)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil, "", errNotInContainer
		}
		if err != nil {
			return nil, "", fmt.Errorf("docker: read archive of %s: %w", filePath, err)
		}

		switch header.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			return nil, header.Linkname, nil
		case tar.TypeReg:
			// A package database is a few megabytes at most; the cap is here so
			// a hostile or broken container cannot make this allocate without
			// bound.
			data, err := io.ReadAll(io.LimitReader(reader, 64<<20))
			return data, "", err
		}
	}
}

// resolveContainerLink resolves a symlink target against the path it was found
// at.
//
// Container paths are always slash-separated, so this uses path rather than
// filepath — on Windows filepath would produce backslashes and ask Docker for
// something that does not exist.
func resolveContainerLink(from, target string) string {
	if strings.HasPrefix(target, "/") {
		return stdpath.Clean(target)
	}
	return stdpath.Clean(stdpath.Join(stdpath.Dir(from), target))
}

// packages reads one container's distribution package list.
func (c *DockerClient) packages(container Container) ([]Package, error) {
	release, err := c.File(container.ID, "/etc/os-release")
	if err != nil {
		if errors.Is(err, errNotInContainer) {
			// A FROM scratch or distroless image has no distribution packages to
			// find, which is a legitimate answer rather than a failure.
			slog.Debug("collect: container has no /etc/os-release",
				"container", container.short(), "image", container.Image)
			return nil, nil
		}
		return nil, err
	}

	ecosystem, dbPath := ecosystemFromOSRelease(release)
	if ecosystem == "" {
		slog.Debug("collect: unrecognised distribution in container",
			"container", container.short(), "image", container.Image)
		return nil, nil
	}

	raw, err := c.File(container.ID, dbPath)
	if err != nil {
		if errors.Is(err, errNotInContainer) {
			return nil, nil
		}
		return nil, err
	}

	var parsed []distroPackage
	if strings.HasSuffix(dbPath, "installed") {
		parsed = parseAPKInstalled(raw)
	} else {
		parsed = parseDpkgStatus(raw)
	}

	label := container.label()
	out := make([]Package, 0, len(parsed))
	for _, item := range parsed {
		out = append(out, Package{
			Ecosystem:  ecosystem,
			Name:       item.name,
			Version:    item.version,
			Scope:      match.ScopeContainer,
			InstallDir: label,
			// Distribution packages have maintainer scripts, but they run at
			// image build time rather than on this machine, so the flag that
			// means "code ran here when you installed it" does not apply.
			HasScripts: false,
		})
	}
	return out, nil
}

type distroPackage struct{ name, version string }

// ecosystemFromOSRelease maps /etc/os-release onto the ecosystem OSV files the
// distribution's advisories under, and the path of its package database.
func ecosystemFromOSRelease(raw []byte) (ecosystem, dbPath string) {
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		fields[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}

	version := fields["VERSION_ID"]
	switch fields["ID"] {
	case "debian":
		return "Debian:" + version, "/var/lib/dpkg/status"
	case "ubuntu":
		// OSV files long-term releases as "Ubuntu:24.04:LTS" and interim ones as
		// "Ubuntu:25.10". Getting this wrong is not a near miss — the lookup
		// returns zero rows, which for the 1,830 packages on an Ubuntu host means
		// every one of them reads as having nothing on file.
		//
		// Taken from os-release rather than from a hardcoded list of LTS
		// versions, which would need editing every two years and would be wrong
		// in between.
		if isLTS(fields) {
			return "Ubuntu:" + version + ":LTS", "/var/lib/dpkg/status"
		}
		return "Ubuntu:" + version, "/var/lib/dpkg/status"
	case "alpine":
		// OSV files Alpine advisories per minor release — "v3.19", not the
		// patch-level 3.19.1 that os-release reports.
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1], "/lib/apk/db/installed"
		}
		return "", ""
	}
	return "", ""
}

// isLTS reads the long-term-support marker out of os-release. Ubuntu puts it in
// VERSION ("24.04.3 LTS (Noble Numbat)") and PRETTY_NAME; either will do.
func isLTS(fields map[string]string) bool {
	return strings.Contains(strings.ToUpper(fields["VERSION"]), "LTS") ||
		strings.Contains(strings.ToUpper(fields["PRETTY_NAME"]), "LTS")
}

// parseDpkgStatus reads Debian's package database.
//
// Only packages whose Status says "install ok installed" count. The file also
// holds records for packages that were removed but left their configuration
// behind, and those are not on the disk to be exploited.
func parseDpkgStatus(raw []byte) []distroPackage {
	var out []distroPackage

	for _, block := range bytes.Split(raw, []byte("\n\n")) {
		var name, version string
		installed := false

		for _, line := range strings.Split(string(block), "\n") {
			key, value, found := strings.Cut(line, ": ")
			if !found {
				continue
			}
			switch key {
			case "Package":
				name = strings.TrimSpace(value)
			case "Version":
				version = strings.TrimSpace(value)
			case "Status":
				installed = strings.Contains(value, "install ok installed")
			}
		}
		if installed && name != "" && version != "" {
			out = append(out, distroPackage{name, version})
		}
	}
	return out
}

// parseAPKInstalled reads Alpine's package database, whose records are single
// letters: P for the package name, V for its version.
func parseAPKInstalled(raw []byte) []distroPackage {
	var out []distroPackage

	for _, block := range bytes.Split(raw, []byte("\n\n")) {
		var name, version string
		for _, line := range strings.Split(string(block), "\n") {
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				name = strings.TrimSpace(line[2:])
			case 'V':
				version = strings.TrimSpace(line[2:])
			}
		}
		if name != "" && version != "" {
			out = append(out, distroPackage{name, version})
		}
	}
	return out
}
