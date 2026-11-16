package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := LoadString(p); err != nil || v != "s3cret" {
		t.Fatalf("%q %v", v, err)
	}
	_ = os.Chmod(p, 0o640)
	if _, err := LoadString(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("group-readable accepted: %v", err)
	}
	// systemd credential by name.
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if err := os.WriteFile(filepath.Join(dir, "ad-bind"), []byte("x"), 0o440); err != nil {
		t.Fatal(err)
	}
	if v, err := LoadString("ad-bind"); err != nil || v != "x" {
		t.Fatalf("credential: %q %v", v, err)
	}
	// Fallback directory for manual runs.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	FallbackDir = dir
	if _, err := LoadString("ad-bind"); err == nil {
		t.Fatal("non-private fallback credential accepted")
	}
	for _, bad := range []string{"../etc/passwd", "a/b", "", "relative/path"} {
		if _, err := Load(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := LoadString(empty); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestLoadRefusesLinksAndForeignOwners(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "key.json")
	if err := os.WriteFile(p, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("0400 owned by the process user refused: %v", err)
	}
	// A symbolic link to a private file is refused: the file is named
	// itself, so nobody can redirect the credential by replacing a link.
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink accepted: %v", err)
	}
	// Owned by another user (simulated by changing the process's uid).
	if os.Geteuid() == 0 {
		t.Skip("running as root: every file is owned by an accepted user")
	}
	old := euid
	euid = func() int { return os.Geteuid() + 1 }
	defer func() { euid = old }()
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("foreign owner accepted: %v", err)
	}
}
