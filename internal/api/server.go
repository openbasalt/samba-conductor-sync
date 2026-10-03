// Package api is `conductor-sync serve`: the local management API that
// conductor's web interface uses (protocol in the public syncapi package),
// plus, optionally, the in-process scheduler.
//
// Security:
//   - a Unix socket only (no network listener), mode 0660, owned by the
//     conductor-sync user and a group the conductor user is in, or handed
//     over by systemd socket activation;
//   - every connection's peer is checked with SO_PEERCRED: only the
//     configured UIDs (default: the conductor user) are served;
//   - requests are typed and allowlisted, decoded strictly, size-bounded;
//   - every mutation (settings, key, plan, apply) is written to the
//     hash-chained audit log with the AD user conductor acted for;
//   - the service account key is accepted (key.set), stored encrypted and
//     never returned; only its client e-mail and key ID are shown.
//
// Plans and applies run as background jobs (one at a time, and the
// engine's run lock still excludes the timer and the CLI); the client polls
// job.get. Timer-driven runs do not need this server.
package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Server is a running management API.
type Server struct {
	rt      *app.Runtime
	log     *slog.Logger
	version string
	// allowedMu guards allowed (replaced in tests).
	allowedMu sync.RWMutex
	allowed   map[int]bool
	ln        *net.UnixListener
	sem       chan struct{}
	wg        sync.WaitGroup
	jobs      *jobs
	now       func() time.Time
	// base is the server's lifetime context (jobs run under it).
	base context.Context
	// peerCred is replaced in tests.
	peerCred func(*net.UnixConn) (uid int, err error)
	// nextScheduled is the in-process scheduler's next run (zero when the
	// systemd timer schedules).
	schedMu       sync.Mutex
	nextScheduled time.Time
}

// Options configure a server.
type Options struct {
	Logger  *slog.Logger
	Version string
	// AllowedUIDs overrides the configuration (tests).
	AllowedUIDs []int
}

// New builds a server for the runtime (not listening yet).
func New(rt *app.Runtime, opt Options) (*Server, error) {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	s := &Server{rt: rt, log: opt.Logger, version: opt.Version, sem: make(chan struct{}, 8), jobs: newJobs(),
		now: time.Now, base: context.Background(), peerCred: peerCredentials, allowed: map[int]bool{}}
	uids := opt.AllowedUIDs
	if uids == nil {
		var err error
		if uids, err = allowedUIDs(rt.File.API); err != nil {
			return nil, err
		}
	}
	for _, u := range uids {
		s.allowed[u] = true
	}
	if len(s.allowed) == 0 {
		return nil, errors.New("api: no peer is allowed (api.allowed_users / api.allowed_uids)")
	}
	return s, nil
}

func allowedUIDs(c config.API) ([]int, error) {
	out := append([]int(nil), c.AllowedUIDs...)
	for _, name := range c.AllowedUsers {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("api.allowed_users: %q: %w", name, err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, nil
}

// Listen opens the socket: the one passed by systemd socket activation
// (LISTEN_FDS) when present, else api.socket created with mode 0660 and
// api.socket_group.
func (s *Server) Listen() error {
	if ln, ok, err := activationListener(); err != nil {
		return err
	} else if ok {
		s.ln = ln
		s.log.Info("management API on the socket passed by systemd")
		return nil
	}
	path := s.rt.File.API.Socket
	if !filepath.IsAbs(path) {
		return errors.New("api: socket path must be absolute")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("api: %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if g := s.rt.File.API.SocketGroup; g != "" {
		gid, err := lookupGroup(g)
		if err != nil {
			_ = ln.Close()
			return err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return fmt.Errorf("api: socket group %s: %w (the service user must be a member)", g, err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return err
	}
	s.ln = ln
	s.log.Info("management API listening", "socket", path)
	return nil
}

func lookupGroup(g string) (int, error) {
	if n, err := strconv.Atoi(g); err == nil {
		return n, nil
	}
	grp, err := user.LookupGroup(g)
	if err != nil {
		return 0, fmt.Errorf("api.socket_group %q: %w", g, err)
	}
	return strconv.Atoi(grp.Gid)
}

// activationListener returns the first socket passed by systemd.
func activationListener() (*net.UnixListener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, false, nil
	}
	f := os.NewFile(3, "systemd-socket")
	l, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, false, fmt.Errorf("api: socket activation: %w", err)
	}
	ul, ok := l.(*net.UnixListener)
	if !ok {
		_ = l.Close()
		return nil, false, errors.New("api: socket activation passed a non-Unix socket")
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	return ul, true, nil
}

// peerCredentials reads SO_PEERCRED of the connection.
func peerCredentials(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}

// Serve accepts connections until ctx ends, then waits for running
// requests; running jobs are cancelled (an interrupted apply is resumed by
// the next run, as after any crash).
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("api: not listening")
	}
	jobCtx, cancelJobs := context.WithCancel(context.WithoutCancel(ctx))
	s.base = jobCtx
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(ctx, c)
		}()
	}
	s.wg.Wait()
	cancelJobs()
	s.jobs.wait(30 * time.Second)
	return nil
}

func (s *Server) serveConn(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	uid, err := s.peerCred(c)
	s.allowedMu.RLock()
	ok := s.allowed[uid]
	s.allowedMu.RUnlock()
	if err != nil || !ok {
		s.log.Warn("connection refused: peer not allowed", "uid", uid, "err", err)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	var req syncapi.Request
	if err := syncapi.ReadMessage(bufio.NewReaderSize(c, 64<<10), &req); err != nil {
		_ = syncapi.WriteMessage(c, syncapi.ErrorResponse("", &syncapi.Error{Code: syncapi.CodeBadRequest, Message: "unreadable request"}))
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Minute))
	rctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	resp := s.Handle(rctx, req)
	if err := syncapi.WriteMessage(c, resp); err != nil {
		s.log.Warn("writing the response failed", "op", req.Op, "err", err)
	}
}
