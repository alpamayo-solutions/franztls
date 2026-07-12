//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package franztls

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type platformDir struct {
	fd   int
	path string
}

func platformOpenDir(path string, create bool, requiredMode fs.FileMode) (*platformDir, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return nil, errUnsafeStatePath
	}

	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = unix.Close(current)
		}
	}()

	trimmed := strings.TrimPrefix(cleaned, string(filepath.Separator))
	if trimmed != "" && trimmed != "." {
		components := strings.Split(trimmed, string(filepath.Separator))
		for index, component := range components {
			if component == "" || component == "." || component == ".." {
				return nil, errUnsafeStatePath
			}
			next, openErr := unix.Openat(
				current,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
			if openErr != nil && create && index == len(components)-1 && errors.Is(openErr, unix.ENOENT) {
				if mkdirErr := unix.Mkdirat(current, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
					return nil, classifyUnixPathError(mkdirErr)
				}
				next, openErr = unix.Openat(
					current,
					component,
					unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
					0,
				)
			}
			if openErr != nil {
				return nil, classifyUnixPathError(openErr)
			}
			if err := unix.Close(current); err != nil {
				_ = unix.Close(next)
				return nil, err
			}
			current = next
		}
	}

	var stat unix.Stat_t
	if err := unix.Fstat(current, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errUnsafeStatePath
	}
	if requiredMode != 0 && fs.FileMode(stat.Mode&0o777) != requiredMode.Perm() {
		return nil, errWrongMode
	}
	keep = true
	return &platformDir{fd: current, path: cleaned}, nil
}

func (d *platformDir) createTemp(prefix string) (atomicFile, string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		fd, err := unix.Openat(
			d.fd,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0o600,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", classifyUnixPathError(err)
		}
		return os.NewFile(uintptr(fd), filepath.Join(d.path, name)), name, nil
	}
	return nil, "", errors.New("franztls: could not create unique temporary state file")
}

func (d *platformDir) remove(name string) error {
	if !safeBaseName(name) {
		return errUnsafeStatePath
	}
	err := unix.Unlinkat(d.fd, name, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return classifyUnixPathError(err)
}

func (d *platformDir) rename(oldName, newName string) error {
	if !safeBaseName(oldName) || !safeBaseName(newName) {
		return errUnsafeStatePath
	}
	return classifyUnixPathError(unix.Renameat(d.fd, oldName, d.fd, newName))
}

func (d *platformDir) sync() error {
	return unix.Fsync(d.fd)
}

func (d *platformDir) close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	return err
}

func (d *platformDir) readFile(name string) ([]byte, fs.FileMode, error) {
	if !safeBaseName(name) {
		return nil, 0, errUnsafeStatePath
	}
	fd, err := unix.Openat(
		d.fd,
		name,
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, 0, classifyUnixPathError(err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errNotRegularFile
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode().Perm(), nil
}

func classifyUnixPathError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return errors.Join(errUnsafeStatePath, err)
	}
	return err
}
