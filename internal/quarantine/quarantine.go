// Package quarantine moves an installed package out of the way and can put it
// back byte for byte.
//
// It is the one part of pkgwatch that deletes something, so every rule here is
// about being able to undo it. The archive is written and verified before the
// original is removed, the digest recorded is of the tree rather than of the
// archive, and a restore that does not reproduce that digest exactly is
// reported as a failure rather than as a restore.
package quarantine

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/myselfvivek17/pkgwatch/internal/match"
)

// Quarantinable scopes.
//
// system and container are refused, and not as a simplification. A system row's
// install_path is /var/lib/dpkg/status — the package manager's own database,
// shared by every package on the machine, so archiving and deleting it to
// neutralise one package would take the OS's record of all of them with it. A
// container row's path is not a path at all: "container:honcho-redis-1
// (redis:8.2)" names something that does not exist on this filesystem.
//
// Both were checked against the real inventory rather than assumed.
var quarantinable = map[string]bool{
	match.ScopeGlobal:  true,
	match.ScopeProject: true,
	match.ScopeVenv:    true,
}

// ErrScope is returned for a package this machine cannot safely quarantine.
type ErrScope struct{ Scope, PURL, Path string }

func (e ErrScope) Error() string {
	switch e.Scope {
	case match.ScopeSystem:
		return fmt.Sprintf("%s is a system package: its recorded path is %s, the package "+
			"manager's own database for every package on this machine. Remove it with the "+
			"system package manager instead", e.PURL, e.Path)
	case match.ScopeContainer:
		return fmt.Sprintf("%s lives in %s, which is not a path on this filesystem. "+
			"Rebuild or replace the image instead — quarantining the host would not touch it",
			e.PURL, e.Path)
	default:
		return fmt.Sprintf("%s has scope %q, which cannot be quarantined", e.PURL, e.Scope)
	}
}

// Archive is a package's files, packed and hashed.
type Archive struct {
	Path   string // where the tar was written
	Digest string // digest of the tree, not of the tar
	Files  int
	Bytes  int64
}

// Pack writes the directory at origin into dir as a tar, and returns the digest
// of what it packed.
//
// The digest covers the tree — every relative path, mode bit and byte of
// content, in sorted order — rather than the archive file. A tar carries
// timestamps and ordering that vary between runs, so hashing it would produce a
// number that cannot be compared with anything later. Hashing the tree gives a
// value a restore can be checked against, which is the whole point of recording
// one.
func Pack(origin, dir, id string) (Archive, error) {
	info, err := os.Stat(origin)
	if err != nil {
		return Archive{}, fmt.Errorf("quarantine: %s is not there to move: %w", origin, err)
	}
	if !info.IsDir() {
		return Archive{}, fmt.Errorf("quarantine: %s is not a directory", origin)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Archive{}, fmt.Errorf("quarantine: create %s: %w", dir, err)
	}
	archivePath := filepath.Join(dir, id+".tar")

	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Archive{}, fmt.Errorf("quarantine: create archive: %w", err)
	}
	defer file.Close()

	writer := tar.NewWriter(file)
	result := Archive{Path: archivePath}

	entries, err := walk(origin)
	if err != nil {
		return Archive{}, err
	}

	digest := sha256.New()
	for _, entry := range entries {
		if err := writeEntry(writer, digest, origin, entry); err != nil {
			return Archive{}, err
		}
		if entry.Mode().IsRegular() {
			result.Files++
			result.Bytes += entry.Size()
		}
	}
	if err := writer.Close(); err != nil {
		return Archive{}, fmt.Errorf("quarantine: finish archive: %w", err)
	}
	if err := file.Sync(); err != nil {
		return Archive{}, fmt.Errorf("quarantine: flush archive: %w", err)
	}

	result.Digest = hex.EncodeToString(digest.Sum(nil))
	return result, nil
}

// entry is one path inside the tree, carried with its relative name so the
// digest and the archive agree on ordering.
type entry struct {
	rel string
	os.FileInfo
	link string
}

// walk lists the tree in a stable order, without following symlinks.
//
// Not following them is a security property, not a convenience: a package that
// links to / would otherwise have the whole filesystem archived, and then
// deleted.
func walk(root string) ([]entry, error) {
	var out []entry
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		item := entry{rel: filepath.ToSlash(rel), FileInfo: info}
		if info.Mode()&os.ModeSymlink != 0 {
			if item.link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		out = append(out, item)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("quarantine: read %s: %w", root, err)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// writeEntry adds one path to the archive and folds it into the digest.
func writeEntry(writer *tar.Writer, digest io.Writer, root string, item entry) error {
	header, err := tar.FileInfoHeader(item.FileInfo, item.link)
	if err != nil {
		return err
	}
	header.Name = item.rel
	// Timestamps are deliberately not preserved. They are the one part of a tree
	// that a restore cannot reproduce identically across filesystems, and a
	// digest that included them would report every correct restore as wrong.
	header.ModTime = time.Time{}
	header.AccessTime = time.Time{}
	header.ChangeTime = time.Time{}

	if err := writer.WriteHeader(header); err != nil {
		return err
	}

	// The digest sees the same facts a restore can check: name, kind, the
	// executable bit, and content.
	fmt.Fprintf(digest, "%s\x00%d\x00%s\x00", item.rel, header.Typeflag, modeFor(item.FileInfo))
	if item.link != "" {
		fmt.Fprintf(digest, "%s\x00", item.link)
	}
	if !item.Mode().IsRegular() {
		return nil
	}

	source, err := os.Open(filepath.Join(root, filepath.FromSlash(item.rel)))
	if err != nil {
		return err
	}
	defer source.Close()

	if _, err := io.Copy(io.MultiWriter(writer, digest), source); err != nil {
		return fmt.Errorf("quarantine: pack %s: %w", item.rel, err)
	}
	return nil
}

// modeFor reduces permissions to what survives a round trip everywhere.
//
// Windows does not carry the full POSIX bits, so a digest over all nine of them
// would make every restore on Windows look like a corrupted one. The executable
// bit is the one that changes what a file *does*, and it is kept.
func modeFor(info os.FileInfo) string {
	if info.Mode()&0o100 != 0 {
		return "x"
	}
	return "-"
}

// Unpack extracts an archive into dir and returns the digest of what it wrote.
//
// The caller compares that digest with the one recorded at quarantine time. A
// restore that does not match must be reported as a failure: the files are back
// but they are not the files that were taken, and "restored" would be a claim
// nobody could check afterwards.
func Unpack(archivePath, dir string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("quarantine: open archive: %w", err)
	}
	defer file.Close()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("quarantine: create %s: %w", dir, err)
	}

	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("quarantine: read archive: %w", err)
		}

		target, err := safeJoin(dir, header.Name)
		if err != nil {
			return "", err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return "", err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return "", err
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				// Creating a symlink on Windows needs either developer mode or
				// an elevated process. Failing here is correct: the alternative
				// is a tree that is missing links and is reported as restored.
				return "", fmt.Errorf("quarantine: restore link %s: %w "+
					"(on Windows this needs Developer Mode or an elevated shell)", header.Name, err)
			}
		default:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY,
				os.FileMode(header.Mode).Perm())
			if err != nil {
				return "", fmt.Errorf("quarantine: restore %s: %w", header.Name, err)
			}
			if _, err := io.Copy(out, reader); err != nil {
				out.Close()
				return "", fmt.Errorf("quarantine: restore %s: %w", header.Name, err)
			}
			if err := out.Close(); err != nil {
				return "", err
			}
		}
	}

	return Digest(dir)
}

// safeJoin refuses a path that would land outside dir.
//
// The archives here are written by this program, but they are files on disk in
// a directory a person can reach, and an extractor that trusts its input is how
// a tarball writes to C:\Windows.
//
// The test caught the interesting half: "/etc/passwd" is not absolute on
// Windows — filepath.IsAbs wants a volume — so a prefix check written on one
// platform passes it on the other. The result is compared against the target
// directory instead, which is the same question asked of the answer rather than
// of the input.
func safeJoin(dir, name string) (string, error) {
	refuse := fmt.Errorf("quarantine: archive entry %q points outside the restore directory", name)

	clean := filepath.FromSlash(name)
	if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" ||
		strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, `\`) {
		return "", refuse
	}

	target := filepath.Join(dir, clean)
	rel, err := filepath.Rel(dir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", refuse
	}
	return target, nil
}

// Digest computes the tree digest of a directory, the same way Pack does.
func Digest(root string) (string, error) {
	entries, err := walk(root)
	if err != nil {
		return "", err
	}

	digest := sha256.New()
	for _, item := range entries {
		typeflag := byte(tar.TypeReg)
		switch {
		case item.IsDir():
			typeflag = tar.TypeDir
		case item.Mode()&os.ModeSymlink != 0:
			typeflag = tar.TypeSymlink
		}

		fmt.Fprintf(digest, "%s\x00%d\x00%s\x00", item.rel, typeflag, modeFor(item.FileInfo))
		if item.link != "" {
			fmt.Fprintf(digest, "%s\x00", item.link)
		}
		if !item.Mode().IsRegular() {
			continue
		}

		source, err := os.Open(filepath.Join(root, filepath.FromSlash(item.rel)))
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(digest, source); err != nil {
			source.Close()
			return "", err
		}
		source.Close()
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// CanQuarantine reports whether a scope may be moved out of the way at all.
func CanQuarantine(scope string) bool { return quarantinable[scope] }
