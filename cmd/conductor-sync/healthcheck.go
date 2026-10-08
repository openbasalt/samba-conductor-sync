package main

import (
	"fmt"
	"io"
	"os"

	"github.com/openbasalt/samba-conductor-sync/internal/config"
)

// healthcheck is the container healthcheck (the image has no shell): the
// configuration loads and `serve` has created its management API socket.
// It opens no database and reads no credential. It does not connect: the
// socket admits only conductor's UID and would refuse (and log) this one.
func healthcheck(cfgPath string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	sock := cfg.API.Socket // the default is filled in by Load
	st, err := os.Stat(sock)
	if err != nil {
		fmt.Fprintln(stderr, "management API socket:", err)
		return exitError
	}
	if st.Mode()&os.ModeSocket == 0 {
		fmt.Fprintf(stderr, "management API socket: %s is not a socket\n", sock)
		return exitError
	}
	fmt.Fprintln(stdout, "ok")
	return exitOK
}
