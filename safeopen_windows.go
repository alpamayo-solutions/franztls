//go:build windows

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
	"unsafe"

	"golang.org/x/sys/windows"
)

type platformDir struct {
	handle windows.Handle
	path   string
}

type fileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

const (
	fileAddSubdirectory    = 0x00000004
	fileDeleteChild        = 0x00000040
	minimalDirectoryAccess = windows.FILE_LIST_DIRECTORY |
		windows.FILE_TRAVERSE |
		windows.FILE_READ_ATTRIBUTES |
		windows.SYNCHRONIZE
)

func platformOpenDir(path string, create bool, _ fs.FileMode) (*platformDir, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return nil, errUnsafeStatePath
	}
	volume := filepath.VolumeName(cleaned)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, &UnsupportedSafeOpenError{GOOS: "windows-unc"}
	}
	directory, err := openWindowsDirectory(cleaned, create, false)
	if err == nil || !create || !windowsPathNotFound(err) {
		return directory, classifyWindowsPathError(err)
	}
	directory, err = openWindowsDirectory(cleaned, true, true)
	return directory, classifyWindowsPathError(err)
}

func openWindowsDirectory(cleaned string, writableFinal, createFinal bool) (*platformDir, error) {
	volume := filepath.VolumeName(cleaned)
	remainder := strings.TrimLeft(strings.TrimPrefix(cleaned, volume), `\/`)
	components := strings.FieldsFunc(remainder, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	if len(components) == 0 {
		return nil, errUnsafeStatePath
	}

	rootName := `\??\` + volume + `\`
	rootAccess := uint32(minimalDirectoryAccess)
	if createFinal && len(components) == 1 {
		rootAccess |= fileAddSubdirectory
	}
	current, err := ntOpenPath(
		0,
		rootName,
		rootAccess,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE,
	)
	if err != nil {
		return nil, classifyWindowsPathError(err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = windows.CloseHandle(current)
		}
	}()
	if err := rejectWindowsReparse(current, true); err != nil {
		return nil, err
	}

	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errUnsafeStatePath
		}
		last := index == len(components)-1
		access := uint32(minimalDirectoryAccess)
		if createFinal && index == len(components)-2 {
			access |= fileAddSubdirectory
		}
		if writableFinal && last {
			access |= windows.FILE_WRITE_DATA | fileDeleteChild
		}
		disposition := uint32(windows.FILE_OPEN)
		if createFinal && last {
			disposition = windows.FILE_OPEN_IF
		}
		next, openErr := ntOpenPath(
			current,
			component,
			access,
			disposition,
			windows.FILE_DIRECTORY_FILE,
		)
		if openErr != nil {
			return nil, openErr
		}
		if err := rejectWindowsReparse(next, true); err != nil {
			_ = windows.CloseHandle(next)
			return nil, err
		}
		if err := windows.CloseHandle(current); err != nil {
			_ = windows.CloseHandle(next)
			return nil, err
		}
		current = next
	}

	keep = true
	return &platformDir{handle: current, path: cleaned}, nil
}

func (d *platformDir) createTemp(prefix string) (atomicFile, string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		handle, err := ntOpenPath(
			d.handle,
			name,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
			windows.FILE_CREATE,
			windows.FILE_NON_DIRECTORY_FILE,
		)
		if err == windows.STATUS_OBJECT_NAME_COLLISION {
			continue
		}
		if err != nil {
			return nil, "", classifyWindowsPathError(err)
		}
		if err := rejectWindowsReparse(handle, false); err != nil {
			_ = windows.CloseHandle(handle)
			return nil, "", err
		}
		return os.NewFile(uintptr(handle), filepath.Join(d.path, name)), name, nil
	}
	return nil, "", errors.New("franztls: could not create unique temporary state file")
}

func (d *platformDir) remove(name string) error {
	handle, err := d.openFile(name, windows.DELETE|windows.SYNCHRONIZE)
	if err == windows.STATUS_OBJECT_NAME_NOT_FOUND {
		return nil
	}
	if err != nil {
		return classifyWindowsPathError(err)
	}
	defer windows.CloseHandle(handle)
	flags := uint32(
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(
		handle,
		&iosb,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
		windows.FileDispositionInformationEx,
	)
}

func (d *platformDir) rename(oldName, newName string) error {
	if !safeBaseName(oldName) || !safeBaseName(newName) {
		return errUnsafeStatePath
	}
	handle, err := d.openFile(oldName, windows.DELETE|windows.SYNCHRONIZE)
	if err != nil {
		return classifyWindowsPathError(err)
	}
	defer windows.CloseHandle(handle)

	newNameUTF16, err := windows.UTF16FromString(newName)
	if err != nil {
		return errUnsafeStatePath
	}
	nameBytes := (len(newNameUTF16) - 1) * 2
	var dummy fileRenameInformation
	bufferSize := int(unsafe.Offsetof(dummy.FileName)) + nameBytes
	buffer := make([]byte, bufferSize)
	information := (*fileRenameInformation)(unsafe.Pointer(&buffer[0]))
	information.ReplaceIfExists = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	information.RootDirectory = d.handle
	information.FileNameLength = uint32(nameBytes)
	copy(
		(*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&information.FileName[0]))[:nameBytes/2:nameBytes/2],
		newNameUTF16,
	)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(
		handle,
		&iosb,
		&buffer[0],
		uint32(bufferSize),
		windows.FileRenameInformation,
	)
}

func (d *platformDir) sync() error {
	return windows.FlushFileBuffers(d.handle)
}

func (d *platformDir) close() error {
	if d == nil || d.handle == 0 || d.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(d.handle)
	d.handle = windows.InvalidHandle
	return err
}

func (d *platformDir) readFile(name string) ([]byte, fs.FileMode, error) {
	handle, err := d.openFile(name, windows.FILE_GENERIC_READ|windows.SYNCHRONIZE)
	if err != nil {
		return nil, 0, classifyWindowsPathError(err)
	}
	if err := rejectWindowsReparse(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, 0, err
	}
	file := os.NewFile(uintptr(handle), filepath.Join(d.path, name))
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, err
	}
	// Windows ACLs, not POSIX mode bits, control access. A zero portable mode
	// tells common code that the no-follow/type checks succeeded but there is no
	// meaningful POSIX permission comparison to perform.
	return data, 0, nil
}

func (d *platformDir) openFile(name string, access uint32) (windows.Handle, error) {
	if !safeBaseName(name) {
		return 0, errUnsafeStatePath
	}
	return ntOpenPath(d.handle, name, access, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
}

func ntOpenPath(root windows.Handle, name string, access, disposition, kindOptions uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, errUnsafeStatePath
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: root,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	var (
		handle windows.Handle
		iosb   windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(
		&handle,
		access,
		attributes,
		&iosb,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		disposition,
		kindOptions|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	return handle, err
}

func rejectWindowsReparse(handle windows.Handle, wantDirectory bool) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errUnsafeStatePath
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory {
		if wantDirectory {
			return errUnsafeStatePath
		}
		return errNotRegularFile
	}
	return nil
}

func classifyWindowsPathError(err error) error {
	if err == nil {
		return nil
	}
	if err == windows.STATUS_REPARSE_POINT_ENCOUNTERED {
		return errors.Join(errUnsafeStatePath, err)
	}
	return err
}

func windowsPathNotFound(err error) bool {
	return err == windows.STATUS_OBJECT_NAME_NOT_FOUND ||
		err == windows.STATUS_OBJECT_PATH_NOT_FOUND
}
