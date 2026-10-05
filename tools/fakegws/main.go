// Command fakegws serves the fake Google Directory API (internal/fakegoogle)
// on a loopback address, for end-to-end runs of the real conductor-sync
// binary in the lab. It is a test tool: never packaged or installed, and it
// refuses to listen on anything but loopback.
//
//	fakegws -dir /path/to/state -addr 127.0.0.1:8443 -domains example.com -org-units /Staff,/Staff/Sales
//
// It writes into -dir: cert.pem (its self-signed TLS certificate, for
// google.ca_file), sa-key.json (0600, the service account key whose token
// endpoint it serves) and admin.txt (the admin subject). Test controls:
//
// For a persistent test environment, -keep-key reuses the key of
// sa-key.json from an earlier run (so a key uploaded to conductor-sync stays
// valid) and -state keeps the directory in a file (saved every few seconds
// and on SIGTERM).
//
//	GET  /_fake/state         users, groups and members as JSON
//	GET  /_fake/writes        the write requests received
//	POST /_fake/fault         queue a fakegoogle.Fault (JSON body)
//	POST /_fake/latency?ms=N  delay every API request
//	POST /_fake/seed          add accounts, groups (members by address) and
//	                          org units directly, as an existing company's
//	                          directory (JSON body, see seedRequest)
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
)

func main() {
	dir := flag.String("dir", "", "directory for cert.pem, sa-key.json and admin.txt")
	addr := flag.String("addr", "127.0.0.1:8443", "loopback listen address")
	domains := flag.String("domains", "example.com", "comma-separated domains")
	ous := flag.String("org-units", "", "comma-separated org unit paths that exist")
	pageSize := flag.Int("page-size", 100, "list page size")
	seedAdmin := flag.Bool("seed-admin", false, "create the admin subject's account (the web UI's connection test reads it)")
	keepKey := flag.Bool("keep-key", false, "reuse the key of an existing sa-key.json in -dir")
	stateFile := flag.String("state", "", "keep the directory in this file across restarts")
	flag.Parse()
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatal("fakegws listens on loopback only")
	}
	fake := fakegoogle.New(strings.Split(*domains, ",")...)
	fake.PageSize = *pageSize
	for _, ou := range strings.Split(*ous, ",") {
		if ou = strings.TrimSpace(ou); ou != "" {
			fake.AddOrgUnit(ou)
		}
	}
	base := "https://" + net.JoinHostPort(host, port)
	fake.SetTokenURL(base + "/token")
	if *keepKey {
		if k, err := loadKey(filepath.Join(*dir, "sa-key.json")); err == nil {
			fake.SetKey(k)
		} else if !os.IsNotExist(err) {
			log.Fatalf("-keep-key: %v", err)
		}
	}
	if *stateFile != "" {
		if b, err := os.ReadFile(*stateFile); err == nil {
			if err := fake.LoadState(b); err != nil {
				log.Fatalf("-state: %v", err)
			}
		} else if !os.IsNotExist(err) {
			log.Fatal(err)
		}
		go persist(fake, *stateFile)
	}
	if _, exists := fake.User(fake.AdminSubject); *seedAdmin && !exists {
		// The administrator the sync acts as, as on a real tenant (the
		// connection test reads it).
		fake.SeedUser(fakegoogle.User{PrimaryEmail: fake.AdminSubject, IsAdmin: true,
			Name: map[string]any{"givenName": "Sync", "familyName": "Administrator"}})
	}
	cert, pemCert, err := selfSigned(host)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "cert.pem"), pemCert, 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "sa-key.json"), fake.KeyJSON(), 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "admin.txt"), []byte(fake.AdminSubject+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", fake)
	mux.HandleFunc("/_fake/state", func(w http.ResponseWriter, r *http.Request) {
		type group struct {
			fakegoogle.Group
			Members []string `json:"members"`
		}
		var groups []group
		for _, g := range fake.Groups() {
			_, m, _ := fake.GroupByEmail(g.Email)
			groups = append(groups, group{g, m})
		}
		writeJSON(w, map[string]any{"users": fake.Users(), "groups": groups, "requests": fake.Requests()})
	})
	mux.HandleFunc("/_fake/writes", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, fake.Writes()) })
	mux.HandleFunc("/_fake/fault", func(w http.ResponseWriter, r *http.Request) {
		var f fakegoogle.Fault
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&f) != nil {
			http.Error(w, "POST a Fault", http.StatusBadRequest)
			return
		}
		fake.Fail(f)
	})
	mux.HandleFunc("/_fake/latency", func(w http.ResponseWriter, r *http.Request) {
		ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
		if r.Method != http.MethodPost || err != nil || ms < 0 {
			http.Error(w, "POST ?ms=N", http.StatusBadRequest)
			return
		}
		fake.SetLatency(time.Duration(ms) * time.Millisecond)
	})
	mux.HandleFunc("/_fake/seed", func(w http.ResponseWriter, r *http.Request) {
		var req seedRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if r.Method != http.MethodPost || dec.Decode(&req) != nil {
			http.Error(w, "POST a seed request", http.StatusBadRequest)
			return
		}
		writeJSON(w, seed(fake, req))
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	fmt.Fprintf(os.Stderr, "fakegws: %s (admin %s), files in %s\n", base, fake.AdminSubject, *dir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// seedRequest is the body of POST /_fake/seed.
type seedRequest struct {
	OrgUnits []string          `json:"org_units"`
	Users    []fakegoogle.User `json:"users"`
	Groups   []seedGroup       `json:"groups"`
}

// seedGroup is a group with its members' addresses (accounts, groups or
// external addresses).
type seedGroup struct {
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	Members     []string `json:"members"`
}

// seed stores the objects directly (no API request is recorded); accounts
// and groups whose address already exists are left as they are.
func seed(fake *fakegoogle.Server, req seedRequest) map[string]int {
	out := map[string]int{}
	for _, ou := range req.OrgUnits {
		fake.AddOrgUnit(ou)
	}
	for _, u := range req.Users {
		if _, exists := fake.User(u.PrimaryEmail); exists {
			out["users_existing"]++
			continue
		}
		fake.SeedUser(u)
		out["users"]++
	}
	ids := map[string]string{}
	for _, g := range req.Groups {
		if _, _, exists := fake.GroupByEmail(g.Email); exists {
			out["groups_existing"]++
			continue
		}
		ids[g.Email] = fake.SeedGroup(fakegoogle.Group{Email: g.Email, Name: g.Name, Description: g.Description, Aliases: g.Aliases}).ID
		out["groups"]++
	}
	for _, g := range req.Groups {
		id, ok := ids[g.Email]
		if !ok {
			continue
		}
		for _, m := range g.Members {
			fake.AddMemberDirect(id, m)
			out["members"]++
		}
	}
	return out
}

// loadKey reads the RSA key of an earlier sa-key.json.
func loadKey(p string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var k struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM key", p)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", p)
	}
	return rk, nil
}

// persist saves the directory every 5 seconds when it changed, and on
// SIGTERM/SIGINT (then exits).
func persist(fake *fakegoogle.Server, p string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	var last []byte
	save := func() {
		b, err := fake.MarshalState()
		if err != nil || bytes.Equal(b, last) {
			return
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err == nil && os.Rename(tmp, p) == nil {
			last = b
		}
	}
	t := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-t.C:
			save()
		case <-sig:
			save()
			os.Exit(0)
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func selfSigned(host string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fakegws"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP(host)},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, pemCert, nil
}
