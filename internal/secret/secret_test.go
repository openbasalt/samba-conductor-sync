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
