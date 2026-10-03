// Package secret loads credentials: a systemd credential by name (from
// $CREDENTIALS_DIRECTORY, set by LoadCredential=) or a file given by
// absolute path that only its owner can read. Values are never logged.
package secret

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	if private {
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("secret: %w", err)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("secret: %s is not a regular file", p)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("secret: %s is readable by group or others (mode %o); chmod 0600", p, st.Mode().Perm())
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	defer func() { _ = f.Close() }()
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
