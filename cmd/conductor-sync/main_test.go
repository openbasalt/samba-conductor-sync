package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"version"}, nil, &out, &errb); rc != exitOK || !strings.Contains(out.String(), "conductor-sync") {
		t.Fatalf("version: %d %q", rc, out.String())
	}
	if rc := run(nil, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("no args: %d", rc)
	}
	if rc := run([]string{"frobnicate"}, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("unknown command: %d", rc)
	}
	errb.Reset()
	if rc := run([]string{"plan", "--config", "/nonexistent.toml"}, nil, &out, &errb); rc != exitError || !strings.Contains(errb.String(), "nonexistent") {
		t.Fatalf("missing config: %d %q", rc, errb.String())
	}
	if rc := run([]string{"apply", "--bogus"}, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("bad flag: %d", rc)
	}
}
