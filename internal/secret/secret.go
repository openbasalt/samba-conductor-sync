// Package secret loads credentials: a systemd credential by name (from
// $CREDENTIALS_DIRECTORY, set by LoadCredential=) or a file given by
// absolute path that only its owner can read. Values are never logged.
//
// A credential file outside $CREDENTIALS_DIRECTORY must be a regular file
// (not a symbolic link), owned by the user the process runs as (or by
// root), and readable by its owner only (mode 0600 or 0400). The checks are
// made on the opened file, so the file can not be swapped between the
// check and the read.
package secret

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var credName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// MaxSize bounds a credential file.
const MaxSize = 64 << 10

// FallbackDir holds credentials by name when $CREDENTIALS_DIRECTORY is not
// set (a manual run outside the systemd unit). Files there must be private
// like any credential path.
var FallbackDir = "/etc/conductor-sync/credentials"

// Load reads the credential. A bare name is a systemd credential (from
// $CREDENTIALS_DIRECTORY, else FallbackDir); a path must be absolute.
// Credential files outside $CREDENTIALS_DIRECTORY must be private (no group
// or other permissions).
func Load(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("secret: empty credential name")
	}
	var p string
	private := true
	switch {
	case filepath.IsAbs(name):
		p = filepath.Clean(name)
	case credName.MatchString(name):
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			// systemd made this copy for this service only.
			p, private = filepath.Join(dir, name), false
		} else if FallbackDir != "" {
			p = filepath.Join(FallbackDir, name)
		} else {
			return nil, fmt.Errorf("secret: credential %q: $CREDENTIALS_DIRECTORY is not set", name)
		}
	default:
		return nil, fmt.Errorf("secret: invalid credential name %q", name)
	}
	flags := os.O_RDONLY
	if private {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(p, flags, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("secret: %s is a symbolic link; name the file itself", p)
		}
		return nil, fmt.Errorf("secret: %w", err)
	}
	defer func() { _ = f.Close() }()
	if private {
		if err := checkPrivate(f, p); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("secret: read %s: %w", p, err)
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("secret: %s is larger than %d bytes", p, MaxSize)
	}
	return b, nil
}

// LoadString reads a one-line secret (a password) and trims the trailing
// newline.
func LoadString(name string) (string, error) {
	b, err := Load(name)
	if err != nil {
		return "", err
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", fmt.Errorf("secret: credential %q is empty", name)
	}
	return s, nil
}

// euid is the effective user ID (replaceable in tests).
var euid = os.Geteuid

// checkPrivate checks an opened credential file: regular, owned by the
// process user or root, no group or other permission.
func checkPrivate(f *os.File, p string) error {
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("secret: %s is not a regular file", p)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secret: %s is readable by group or others (mode %o); chmod 0600", p, st.Mode().Perm())
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("secret: %s: cannot read the owner", p)
	}
	if uid := int(sys.Uid); uid != euid() && uid != 0 {
		return fmt.Errorf("secret: %s is owned by uid %d, not by this process's user (uid %d) or root; chown it", p, uid, euid())
	}
	return nil
}
