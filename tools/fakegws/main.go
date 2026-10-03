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
//	GET  /_fake/state         users, groups and members as JSON
//	GET  /_fake/writes        the write requests received
//	POST /_fake/fault         queue a fakegoogle.Fault (JSON body)
//	POST /_fake/latency?ms=N  delay every API request
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/fakegoogle"
)

func main() {
	dir := flag.String("dir", "", "directory for cert.pem, sa-key.json and admin.txt")
	addr := flag.String("addr", "127.0.0.1:8443", "loopback listen address")
	domains := flag.String("domains", "example.com", "comma-separated domains")
	ous := flag.String("org-units", "", "comma-separated org unit paths that exist")
	pageSize := flag.Int("page-size", 100, "list page size")
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
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	fmt.Fprintf(os.Stderr, "fakegws: %s (admin %s), files in %s\n", base, fake.AdminSubject, *dir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
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
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
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
