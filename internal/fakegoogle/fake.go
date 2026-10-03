// Package fakegoogle is an in-memory fake of the parts of Google's Admin
// SDK Directory API and OAuth token endpoint that conductor-sync uses. It
// exists so the sync is tested end to end without ever writing to a real
// Workspace: users (with aliases after a rename, externalIds,
// organizations, phones), groups, members (users, groups, external
// addresses), org units, pagination, the JWT bearer grant with
// domain-wide delegation scopes, and injected failures (rate limits,
// server errors, writes that succeed but answer with an error).
package fakegoogle

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scope URLs.
const (
	ScopeUser          = "https://www.googleapis.com/auth/admin.directory.user"
	ScopeUserReadonly  = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	ScopeGroup         = "https://www.googleapis.com/auth/admin.directory.group"
	ScopeGroupReadonly = "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

// User is a stored account.
type User struct {
	ID                 string           `json:"id"`
	PrimaryEmail       string           `json:"primaryEmail"`
	Name               map[string]any   `json:"name,omitempty"`
	Suspended          bool             `json:"suspended"`
	OrgUnitPath        string           `json:"orgUnitPath"`
	IsAdmin            bool             `json:"isAdmin"`
	Aliases            []string         `json:"aliases,omitempty"`
	ExternalIDs        []map[string]any `json:"externalIds,omitempty"`
	Organizations      []map[string]any `json:"organizations,omitempty"`
	Phones             []map[string]any `json:"phones,omitempty"`
	ChangePasswordNext bool             `json:"changePasswordAtNextLogin"`
	// PasswordSet records that a password was given (the value is dropped).
	PasswordSet bool `json:"-"`
}

// Group is a stored group.
type Group struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases,omitempty"`
	// members keyed by member ID (external addresses use "ext:"+email).
	members map[string]*Member
}

// Member is one membership.
type Member struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Type  string `json:"type"`
}

// Fault is an injected failure, matched in order.
type Fault struct {
	Method     string // "" = any
	PathPrefix string // under /admin/directory/v1 ("" = any)
	Status     int
	Reason     string
	RetryAfter int
	// Count is how many matching requests fail (default 1).
	Count int
	// AfterCommit performs the request, then answers with the error: the
	// write happened but the client cannot know it.
	AfterCommit bool
}

// Write is one recorded write request.
type Write struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// Server is the fake.
type Server struct {
	mu sync.Mutex

	Domains      []string
	AdminSubject string
	ClientEmail  string
	// Delegated are the scopes authorized for the client (domain-wide
	// delegation); a token request for any other scope is refused.
	Delegated map[string]bool
	// PageSize caps list pages (small values exercise pagination).
	PageSize int
	// Latency delays every API request.
	Latency time.Duration
	// RateLimitEvery answers 429 to every Nth API request (0 = never).
	RateLimitEvery int

	key      *rsa.PrivateKey
	tokenURL string
	tokens   map[string]map[string]bool

	users    map[string]*User
	groups   map[string]*Group
	orgUnits map[string]bool
	faults   []*Fault
	writes   []Write
	requests int
	nextID   int
}

// New builds a fake for the given domains.
func New(domains ...string) *Server {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Server{
		Domains:      domains,
		AdminSubject: "admin@" + domains[0],
		ClientEmail:  "sync@project.iam.gserviceaccount.com",
		Delegated:    map[string]bool{ScopeUser: true, ScopeUserReadonly: true, ScopeGroup: true, ScopeGroupReadonly: true},
		PageSize:     100,
		key:          k,
		tokens:       map[string]map[string]bool{},
		users:        map[string]*User{},
		groups:       map[string]*Group{},
		orgUnits:     map[string]bool{"/": true},
		nextID:       100000,
	}
}

// SetTokenURL tells the fake its own token URL (the JWT audience).
func (s *Server) SetTokenURL(u string) {
	s.mu.Lock()
	s.tokenURL = u
	s.mu.Unlock()
}

// KeyJSON returns a service account key file for the fake's key.
func (s *Server) KeyJSON() []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(s.key)
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	s.mu.Lock()
	tu := s.tokenURL
	s.mu.Unlock()
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": s.ClientEmail, "private_key_id": "fake-key",
		"private_key": string(p), "token_uri": tu,
	})
	return b
}

// PrivateKey returns the fake's RSA key.
func (s *Server) PrivateKey() *rsa.PrivateKey { return s.key }

// AddOrgUnit registers an org unit path (and its parents).
func (s *Server) AddOrgUnit(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := path; p != "" && p != "/"; p = p[:strings.LastIndex(p, "/")] {
		s.orgUnits[p] = true
	}
}

// Fail queues a fault.
func (s *Server) Fail(f Fault) {
	if f.Count == 0 {
		f.Count = 1
	}
	s.mu.Lock()
	s.faults = append(s.faults, &f)
	s.mu.Unlock()
}

// ClearFaults drops queued faults.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	s.faults = nil
	s.mu.Unlock()
}

func (s *Server) newID() string {
	s.nextID++
	return strconv.Itoa(s.nextID)
}

// SeedUser stores an account directly (an account that exists before the
// sync, e.g. created by hand).
func (s *Server) SeedUser(u User) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == "" {
		u.ID = s.newID()
	}
	if u.OrgUnitPath == "" {
		u.OrgUnitPath = "/"
	}
	u.PrimaryEmail = strings.ToLower(u.PrimaryEmail)
	c := u
	s.users[c.ID] = &c
	return &c
}

// SeedGroup stores a group directly.
func (s *Server) SeedGroup(g Group) *Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.ID == "" {
		g.ID = s.newID()
	}
	g.Email = strings.ToLower(g.Email)
	c := g
	c.members = map[string]*Member{}
	s.groups[c.ID] = &c
	return &c
}

// AddMemberDirect adds a member without the API (manual additions).
func (s *Server) AddMemberDirect(groupID, email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.groups[groupID]
	email = strings.ToLower(email)
	if u := s.userByKey(email); u != nil {
		g.members[u.ID] = &Member{ID: u.ID, Email: u.PrimaryEmail, Role: "MEMBER", Type: "USER"}
		return
	}
	g.members["ext:"+email] = &Member{Email: email, Role: "MEMBER", Type: "EXTERNAL"}
}

// DeleteUserDirect removes an account without the API (an admin deleting
// it by hand).
func (s *Server) DeleteUserDirect(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	for _, g := range s.groups {
		delete(g.members, id)
	}
}

// SuspendDirect suspends an account without the API (another admin).
func (s *Server) SuspendDirect(id string, suspended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[id]; u != nil {
		u.Suspended = suspended
	}
}

// User returns a copy of the account with this ID or address.
func (s *Server) User(key string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.userByKey(key)
	if u == nil {
		return User{}, false
	}
	return *u, true
}

// Users returns copies of every account, sorted by address.
func (s *Server) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrimaryEmail < out[j].PrimaryEmail })
	return out
}

// GroupByEmail returns a copy of a group and its member addresses.
func (s *Server) GroupByEmail(email string) (Group, []string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.groupByKey(email)
	if g == nil {
		return Group{}, nil, false
	}
	var members []string
	for _, m := range g.members {
		members = append(members, m.Email)
	}
	sort.Strings(members)
	c := *g
	c.members = nil
	return c, members, true
}

// Groups returns copies of every group.
func (s *Server) Groups() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		c := *g
		c.members = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// Writes returns the recorded write requests.
func (s *Server) Writes() []Write {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Write(nil), s.writes...)
}

// Requests counts API requests.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// ResetCounters clears the write log and the request counter.
func (s *Server) ResetCounters() {
	s.mu.Lock()
	s.writes = nil
	s.requests = 0
	s.mu.Unlock()
}

func (s *Server) userByKey(key string) *User {
	if u, ok := s.users[key]; ok {
		return u
	}
	key = strings.ToLower(key)
	for _, u := range s.users {
		if u.PrimaryEmail == key {
			return u
		}
		for _, a := range u.Aliases {
			if strings.ToLower(a) == key {
				return u
			}
		}
	}
	return nil
}

func (s *Server) groupByKey(key string) *Group {
	if g, ok := s.groups[key]; ok {
		return g
	}
	key = strings.ToLower(key)
	for _, g := range s.groups {
		if g.Email == key {
			return g
		}
		for _, a := range g.Aliases {
			if strings.ToLower(a) == key {
				return g
			}
		}
	}
	return nil
}

func (s *Server) addressTaken(email string) bool {
	return s.userByKey(email) != nil || s.groupByKey(email) != nil
}

func (s *Server) domainOK(email string) bool {
	_, d, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return false
	}
	for _, x := range s.Domains {
		if strings.EqualFold(x, d) {
			return true
		}
	}
	return false
}

// ServeHTTP routes /token and /admin/directory/v1/*.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/token":
		s.token(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/directory/v1/"):
		s.api(w, r)
	default:
		writeErr(w, http.StatusNotFound, "notFound", "unknown endpoint")
	}
}

func writeErr(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": status, "message": msg, "errors": []map[string]string{{"reason": reason, "message": msg, "domain": "global"}},
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func b64dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// token implements the JWT bearer grant with RS256 verification.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	tokenErr := func(code, desc string) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": desc})
	}
	if r.Method != http.MethodPost {
		tokenErr("invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		tokenErr("invalid_request", "bad form")
		return
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		tokenErr("unsupported_grant_type", "jwt-bearer only")
		return
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if len(parts) != 3 {
		tokenErr("invalid_grant", "malformed assertion")
		return
	}
	sig, err := b64dec(parts[2])
	if err != nil {
		tokenErr("invalid_grant", "bad signature encoding")
		return
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		tokenErr("invalid_grant", "Invalid JWT Signature.")
		return
	}
	cb, err := b64dec(parts[1])
	if err != nil {
		tokenErr("invalid_grant", "bad claims")
		return
	}
	var claims struct {
		Iss   string `json:"iss"`
		Sub   string `json:"sub"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}
	if json.Unmarshal(cb, &claims) != nil {
		tokenErr("invalid_grant", "bad claims")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	switch {
	case claims.Iss != s.ClientEmail:
		tokenErr("invalid_grant", "unknown issuer")
		return
	case s.tokenURL != "" && claims.Aud != s.tokenURL:
		tokenErr("invalid_grant", "Invalid JWT: audience")
		return
	case claims.Exp < now || claims.Iat > now+300 || claims.Exp-claims.Iat > 3600:
		tokenErr("invalid_grant", "Invalid JWT: Token must be a short-lived token")
		return
	case !strings.EqualFold(claims.Sub, s.AdminSubject):
		tokenErr("unauthorized_client", "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested.")
		return
	}
	scopes := map[string]bool{}
	for _, sc := range strings.Fields(claims.Scope) {
		if !s.Delegated[sc] {
			tokenErr("unauthorized_client", "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested.")
			return
		}
		scopes[sc] = true
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := "fake-" + hex.EncodeToString(b)
	s.tokens[tok] = scopes
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": 3600, "token_type": "Bearer"})
}

func (s *Server) takeFault(method, path string) *Fault {
	for i, f := range s.faults {
		if (f.Method == "" || f.Method == method) && strings.HasPrefix(path, f.PathPrefix) {
			c := *f
			f.Count--
			if f.Count <= 0 {
				s.faults = append(s.faults[:i], s.faults[i+1:]...)
			}
			return &c
		}
	}
	return nil
}

type recorder struct {
	status int
	header http.Header
	body   []byte
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { r.body = append(r.body, b...); return len(b), nil }
func (r *recorder) WriteHeader(code int)        { r.status = code }

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if s.Latency > 0 {
		time.Sleep(s.Latency)
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/directory/v1")
	s.mu.Lock()
	s.requests++
	n := s.requests
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	scopes, ok := s.tokens[auth]
	every := s.RateLimitEvery
	fault := s.takeFault(r.Method, path)
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return
	}
	write := r.Method != http.MethodGet
	need := []string{ScopeUserReadonly, ScopeUser}
	if strings.HasPrefix(path, "/groups") {
		need = []string{ScopeGroupReadonly, ScopeGroup}
	}
	if write {
		need = need[1:]
	}
	allowed := false
	for _, sc := range need {
		allowed = allowed || scopes[sc]
	}
	if !allowed {
		writeErr(w, http.StatusForbidden, "insufficientPermissions", "Request had insufficient authentication scopes.")
		return
	}
	if every > 0 && n%every == 0 {
		w.Header().Set("Retry-After", "0")
		writeErr(w, http.StatusTooManyRequests, "rateLimitExceeded", "Rate Limit Exceeded")
		return
	}
	if fault != nil && !fault.AfterCommit {
		if fault.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(fault.RetryAfter))
		}
		writeErr(w, fault.Status, fault.Reason, "injected failure")
		return
	}
	rec := &recorder{status: http.StatusOK, header: http.Header{}}
	s.mu.Lock()
	s.route(rec, r, path)
	if write {
		s.writes = append(s.writes, Write{Method: r.Method, Path: path, Status: rec.status})
	}
	s.mu.Unlock()
	if fault != nil && fault.AfterCommit {
		writeErr(w, fault.Status, fault.Reason, "injected failure after commit")
		return
	}
	for k, v := range rec.header {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.body)
}

func segments(path string) []string {
	var out []string
	for _, p := range strings.Split(strings.Trim(path, "/"), "/") {
		u, err := url.PathUnescape(p)
		if err != nil {
			u = p
		}
		out = append(out, u)
	}
	return out
}

func readBody(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// route handles one API request with s.mu held.
func (s *Server) route(w http.ResponseWriter, r *http.Request, path string) {
	seg := segments(path)
	switch {
	case len(seg) == 1 && seg[0] == "users" && r.Method == http.MethodGet:
		s.listUsers(w, r)
	case len(seg) == 1 && seg[0] == "users" && r.Method == http.MethodPost:
		s.insertUser(w, r)
	case len(seg) == 2 && seg[0] == "users":
		u := s.userByKey(seg[1])
		if u == nil {
			writeErr(w, http.StatusNotFound, "notFound", "Resource Not Found: userKey")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, u)
		case http.MethodPatch, http.MethodPut:
			s.patchUser(w, r, u)
		case http.MethodDelete:
			delete(s.users, u.ID)
			for _, g := range s.groups {
				delete(g.members, u.ID)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "badRequest", "method")
		}
	case len(seg) == 1 && seg[0] == "groups" && r.Method == http.MethodGet:
		s.listGroups(w, r)
	case len(seg) == 1 && seg[0] == "groups" && r.Method == http.MethodPost:
		s.insertGroup(w, r)
	case len(seg) == 2 && seg[0] == "groups":
		g := s.groupByKey(seg[1])
		if g == nil {
			writeErr(w, http.StatusNotFound, "notFound", "Resource Not Found: groupKey")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, g)
		case http.MethodPatch, http.MethodPut:
			s.patchGroup(w, r, g)
		case http.MethodDelete:
			delete(s.groups, g.ID)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "badRequest", "method")
		}
	case len(seg) >= 3 && seg[0] == "groups" && seg[2] == "members":
		g := s.groupByKey(seg[1])
		if g == nil {
			writeErr(w, http.StatusNotFound, "notFound", "Resource Not Found: groupKey")
			return
		}
		s.members(w, r, g, seg[3:])
	default:
		writeErr(w, http.StatusNotFound, "notFound", "unknown resource")
	}
}

func (s *Server) page(r *http.Request, n int) (start, end int, next string) {
	size := s.PageSize
	if m, err := strconv.Atoi(r.URL.Query().Get("maxResults")); err == nil && m > 0 && m < size {
		size = m
	}
	start, _ = strconv.Atoi(r.URL.Query().Get("pageToken"))
	if start < 0 || start > n {
		start = n
	}
	end = start + size
	if end >= n {
		return start, n, ""
	}
	return start, end, strconv.Itoa(end)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	all := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		all = append(all, u)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	start, end, next := s.page(r, len(all))
	out := map[string]any{"users": all[start:end]}
	if next != "" {
		out["nextPageToken"] = next
	}
	writeJSON(w, http.StatusOK, out)
}

func validName(n map[string]any) bool {
	g, _ := n["givenName"].(string)
	f, _ := n["familyName"].(string)
	return strings.TrimSpace(g) != "" && strings.TrimSpace(f) != "" && len(g) <= 60 && len(f) <= 60
}

func (s *Server) insertUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PrimaryEmail       string           `json:"primaryEmail"`
		Name               map[string]any   `json:"name"`
		Password           string           `json:"password"`
		ChangePasswordNext bool             `json:"changePasswordAtNextLogin"`
		Suspended          bool             `json:"suspended"`
		OrgUnitPath        string           `json:"orgUnitPath"`
		ExternalIDs        []map[string]any `json:"externalIds"`
		Organizations      []map[string]any `json:"organizations"`
		Phones             []map[string]any `json:"phones"`
	}
	if err := readBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid JSON")
		return
	}
	email := strings.ToLower(in.PrimaryEmail)
	switch {
	case !s.domainOK(email):
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: primary_user_email")
		return
	case !validName(in.Name):
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid Given/Family Name")
		return
	case len(in.Password) < 8 || len(in.Password) > 100:
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid Password")
		return
	case in.OrgUnitPath != "" && !s.orgUnits[in.OrgUnitPath]:
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: INVALID_OU_ID")
		return
	case s.addressTaken(email):
		writeErr(w, http.StatusConflict, "duplicate", "Entity already exists.")
		return
	}
	if in.OrgUnitPath == "" {
		in.OrgUnitPath = "/"
	}
	u := &User{ID: s.newID(), PrimaryEmail: email, Name: in.Name, Suspended: in.Suspended, OrgUnitPath: in.OrgUnitPath,
		ExternalIDs: in.ExternalIDs, Organizations: in.Organizations, Phones: in.Phones,
		ChangePasswordNext: in.ChangePasswordNext, PasswordSet: true}
	s.users[u.ID] = u
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request, u *User) {
	var in map[string]json.RawMessage
	if err := readBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid JSON")
		return
	}
	c := *u
	for k, v := range in {
		var err error
		switch k {
		case "primaryEmail":
			var e string
			err = json.Unmarshal(v, &e)
			e = strings.ToLower(e)
			if err == nil && e != c.PrimaryEmail {
				if !s.domainOK(e) {
					writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: primary_user_email")
					return
				}
				if other := s.userByKey(e); (other != nil && other.ID != u.ID) || s.groupByKey(e) != nil {
					writeErr(w, http.StatusConflict, "duplicate", "Entity already exists.")
					return
				}
				// Google keeps the old address as an alias.
				aliases := []string{c.PrimaryEmail}
				for _, a := range c.Aliases {
					if !strings.EqualFold(a, e) {
						aliases = append(aliases, a)
					}
				}
				c.Aliases, c.PrimaryEmail = aliases, e
			}
		case "name":
			var n map[string]any
			err = json.Unmarshal(v, &n)
			if err == nil && !validName(n) {
				writeErr(w, http.StatusBadRequest, "invalid", "Invalid Given/Family Name")
				return
			}
			c.Name = n
		case "suspended":
			err = json.Unmarshal(v, &c.Suspended)
		case "orgUnitPath":
			err = json.Unmarshal(v, &c.OrgUnitPath)
			if err == nil && !s.orgUnits[c.OrgUnitPath] {
				writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: INVALID_OU_ID")
				return
			}
		case "externalIds":
			err = json.Unmarshal(v, &c.ExternalIDs)
		case "organizations":
			err = json.Unmarshal(v, &c.Organizations)
		case "phones":
			err = json.Unmarshal(v, &c.Phones)
		default:
			writeErr(w, http.StatusBadRequest, "invalid", "unsupported field "+k)
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid", "Invalid value for "+k)
			return
		}
	}
	*u = c
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	all := make([]*Group, 0, len(s.groups))
	for _, g := range s.groups {
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	start, end, next := s.page(r, len(all))
	out := map[string]any{"groups": all[start:end]}
	if next != "" {
		out["nextPageToken"] = next
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) insertGroup(w http.ResponseWriter, r *http.Request) {
	var in Group
	if err := readBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid JSON")
		return
	}
	email := strings.ToLower(in.Email)
	switch {
	case !s.domainOK(email):
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: email")
		return
	case s.addressTaken(email):
		writeErr(w, http.StatusConflict, "duplicate", "Entity already exists.")
		return
	}
	g := &Group{ID: s.newID(), Email: email, Name: in.Name, Description: in.Description, members: map[string]*Member{}}
	if g.Name == "" {
		g.Name = email
	}
	s.groups[g.ID] = g
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request, g *Group) {
	var in map[string]json.RawMessage
	if err := readBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "Invalid JSON")
		return
	}
	c := *g
	for k, v := range in {
		var err error
		switch k {
		case "email":
			var e string
			err = json.Unmarshal(v, &e)
			e = strings.ToLower(e)
			if err == nil && e != c.Email {
				if !s.domainOK(e) {
					writeErr(w, http.StatusBadRequest, "invalid", "Invalid Input: email")
					return
				}
				if other := s.groupByKey(e); (other != nil && other.ID != g.ID) || s.userByKey(e) != nil {
					writeErr(w, http.StatusConflict, "duplicate", "Entity already exists.")
					return
				}
				c.Aliases = append(c.Aliases, c.Email)
				c.Email = e
			}
		case "name":
			err = json.Unmarshal(v, &c.Name)
		case "description":
			err = json.Unmarshal(v, &c.Description)
		case "id":
		default:
			writeErr(w, http.StatusBadRequest, "invalid", "unsupported field "+k)
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid", "Invalid value for "+k)
			return
		}
	}
	*g = c
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) members(w http.ResponseWriter, r *http.Request, g *Group, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		all := make([]*Member, 0, len(g.members))
		for _, m := range g.members {
			all = append(all, m)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Email < all[j].Email })
		start, end, next := s.page(r, len(all))
		out := map[string]any{"members": all[start:end]}
		if next != "" {
			out["nextPageToken"] = next
		}
		writeJSON(w, http.StatusOK, out)
	case len(rest) == 0 && r.Method == http.MethodPost:
		var in Member
		if err := readBody(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid", "Invalid JSON")
			return
		}
		key := in.ID
		if key == "" {
			key = in.Email
		}
		var m *Member
		if u := s.userByKey(key); u != nil {
			m = &Member{ID: u.ID, Email: u.PrimaryEmail, Type: "USER"}
		} else if sub := s.groupByKey(key); sub != nil {
			if sub.ID == g.ID {
				writeErr(w, http.StatusBadRequest, "invalid", "a group cannot contain itself")
				return
			}
			m = &Member{ID: sub.ID, Email: sub.Email, Type: "GROUP"}
		} else if in.Email != "" && !s.domainOK(in.Email) {
			m = &Member{Email: strings.ToLower(in.Email), Type: "EXTERNAL"}
		} else {
			writeErr(w, http.StatusNotFound, "notFound", "Resource Not Found: memberKey")
			return
		}
		m.Role = in.Role
		if m.Role == "" {
			m.Role = "MEMBER"
		}
		id := m.ID
		if id == "" {
			id = "ext:" + m.Email
		}
		if _, dup := g.members[id]; dup {
			writeErr(w, http.StatusConflict, "duplicate", "Member already exists.")
			return
		}
		g.members[id] = m
		writeJSON(w, http.StatusOK, m)
	case len(rest) == 1 && r.Method == http.MethodDelete:
		key := strings.ToLower(rest[0])
		for id, m := range g.members {
			if id == rest[0] || m.Email == key || id == "ext:"+key {
				delete(g.members, id)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeErr(w, http.StatusNotFound, "notFound", "Resource Not Found: memberKey")
	default:
		writeErr(w, http.StatusMethodNotAllowed, "badRequest", fmt.Sprintf("members: %s", r.Method))
	}
}
