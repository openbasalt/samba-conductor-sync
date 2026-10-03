// Package google is the Google Workspace connector: the Admin SDK
// Directory API (users, groups, members) called directly over HTTPS with a
// service account and domain-wide delegation. No Google client library is
// used; the handful of endpoints are small and this keeps the dependency
// tree (and its supply chain) minimal.
//
// Ownership: every account the sync creates or adopts carries an
// externalIds entry {type: "custom", customType: <marker>, value: <AD
// objectGUID>}. Accounts without it are never changed unless the operator
// adopts them explicitly.
package google

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/connector"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
)

// Config is the [google] section of the configuration.
type Config struct {
	// Customer is the customer ID ("my_customer" = the admin's own).
	Customer string `toml:"customer"`
	// AdminSubject is the administrator the service account acts as.
	AdminSubject string `toml:"admin_subject"`
	// KeyCredential names the service account JSON key: a systemd
	// credential name or an absolute path to a 0600 file. Optional when
	// the key is set through the management API (stored encrypted in the
	// state database, which then takes precedence).
	KeyCredential string `toml:"key_credential,omitempty"`
	// Marker is the externalIds customType that marks owned accounts. Two
	// sync instances writing to one tenant must use different markers.
	Marker string `toml:"marker"`
	// APIBaseURL and TokenURL exist for tests and proxies; both must be
	// HTTPS.
	APIBaseURL string `toml:"api_base_url"`
	TokenURL   string `toml:"token_url,omitempty"`
	// CAFile adds a CA for APIBaseURL/TokenURL (a TLS-inspecting proxy or
	// a test server). Leave empty for Google.
	CAFile            string   `toml:"ca_file,omitempty"`
	RequestsPerSecond float64  `toml:"requests_per_second"`
	MaxRetries        int      `toml:"max_retries"`
	Timeout           Duration `toml:"timeout"`
	// MemberRole of added members (MEMBER).
	MemberRole string `toml:"member_role"`
}

// Duration decodes "30s" style TOML strings.
type Duration struct{ time.Duration }

// MarshalText implements encoding.TextMarshaler (configuration export).
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.Duration.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Defaults fills unset fields.
func (c *Config) Defaults() {
	if c.Customer == "" {
		c.Customer = "my_customer"
	}
	if c.Marker == "" {
		c.Marker = "conductor-sync"
	}
	if c.APIBaseURL == "" {
		c.APIBaseURL = "https://admin.googleapis.com"
	}
	if c.RequestsPerSecond == 0 {
		c.RequestsPerSecond = 5
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 6
	}
	if c.Timeout.Duration == 0 {
		c.Timeout.Duration = 60 * time.Second
	}
	if c.MemberRole == "" {
		c.MemberRole = "MEMBER"
	}
}

// Validate checks the section (after Defaults).
func (c *Config) Validate() error {
	var errs []error
	if c.AdminSubject == "" || !strings.Contains(c.AdminSubject, "@") {
		errs = append(errs, errors.New("google.admin_subject: the administrator address to act as is required"))
	}
	for name, raw := range map[string]string{"api_base_url": c.APIBaseURL, "token_url": c.TokenURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("google.%s must be an https URL", name))
		}
	}
	if c.RequestsPerSecond < 0 || c.MaxRetries < 0 {
		errs = append(errs, errors.New("google: requests_per_second and max_retries must not be negative"))
	}
	if strings.ContainsAny(c.Marker, " \t\r\n") || len(c.Marker) > 64 {
		errs = append(errs, errors.New("google.marker: one word, at most 64 characters"))
	}
	switch c.MemberRole {
	case "MEMBER", "MANAGER", "OWNER":
	default:
		errs = append(errs, fmt.Errorf("google.member_role %q: want MEMBER, MANAGER or OWNER", c.MemberRole))
	}
	return errors.Join(errs...)
}

// Connector implements connector.Connector for Google Workspace.
type Connector struct {
	cfg Config
	c   *client

	mu  sync.Mutex
	raw map[string]*apiUser // last-read accounts, for merging list fields
}

// Options tune a connector (tests).
type Options struct {
	// HTTPClient replaces the default client (it must still verify TLS).
	HTTPClient *http.Client
	// Backoff is the first retry delay (default 1s), MaxBackoff the cap
	// (default 64s).
	Backoff, MaxBackoff time.Duration
	Sleep               func(context.Context, time.Duration) error
	Now                 func() time.Time
}

// New builds a connector. write selects the write scopes (apply, delete);
// planning uses the read-only scopes.
func New(cfg Config, key *ServiceAccountKey, write bool, opt Options) (*Connector, error) {
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	base, err := url.Parse(cfg.APIBaseURL)
	if err != nil {
		return nil, err
	}
	hc := opt.HTTPClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pemCA, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("google.ca_file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pemCA) {
				return nil, errors.New("google.ca_file: no certificate found")
			}
			tr.TLSClientConfig.RootCAs = pool
		}
		hc = &http.Client{Transport: tr, Timeout: cfg.Timeout.Duration}
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = key.TokenURI
	}
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if u, err := url.Parse(tokenURL); err != nil || u.Scheme != "https" {
		return nil, errors.New("google: the token URL must be https")
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	sleep := opt.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	scopes := ReadScopes
	if write {
		scopes = WriteScopes
	}
	backoff, maxBackoff := opt.Backoff, opt.MaxBackoff
	if backoff <= 0 {
		backoff = time.Second
	}
	if maxBackoff <= 0 {
		maxBackoff = 64 * time.Second
	}
	var interval time.Duration
	if cfg.RequestsPerSecond > 0 {
		interval = time.Duration(float64(time.Second) / cfg.RequestsPerSecond)
	}
	c := &client{base: base, hc: hc, lim: &limiter{interval: interval}, maxRetries: cfg.MaxRetries,
		backoff: backoff, maxBackoff: maxBackoff, now: now, sleep: sleep,
		tokens: &tokenSource{key: key, subject: cfg.AdminSubject, scopes: scopes, tokenURL: tokenURL, hc: hc, now: now}}
	return &Connector{cfg: cfg, c: c, raw: map[string]*apiUser{}}, nil
}

// Name implements connector.Connector.
func (g *Connector) Name() string { return "google" }

// Stats returns HTTP requests and retries so far.
func (g *Connector) Stats() (requests, retries int) { return g.c.stats() }

const apiPrefix = "/admin/directory/v1"

// API resource shapes (only the fields the sync reads or writes).
type apiName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type apiUser struct {
	ID                 string           `json:"id,omitempty"`
	PrimaryEmail       string           `json:"primaryEmail,omitempty"`
	Name               *apiName         `json:"name,omitempty"`
	Suspended          bool             `json:"suspended"`
	OrgUnitPath        string           `json:"orgUnitPath,omitempty"`
	IsAdmin            bool             `json:"isAdmin,omitempty"`
	IsDelegatedAdmin   bool             `json:"isDelegatedAdmin,omitempty"`
	Aliases            []string         `json:"aliases,omitempty"`
	NonEditableAliases []string         `json:"nonEditableAliases,omitempty"`
	ExternalIDs        []map[string]any `json:"externalIds,omitempty"`
	Organizations      []map[string]any `json:"organizations,omitempty"`
	Phones             []map[string]any `json:"phones,omitempty"`
}

type apiGroup struct {
	ID                 string   `json:"id,omitempty"`
	Email              string   `json:"email,omitempty"`
	Name               string   `json:"name,omitempty"`
	Description        string   `json:"description"`
	Aliases            []string `json:"aliases,omitempty"`
	NonEditableAliases []string `json:"nonEditableAliases,omitempty"`
}

type apiMember struct {
	ID     string `json:"id,omitempty"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role,omitempty"`
	Type   string `json:"type,omitempty"`
	Status string `json:"status,omitempty"`
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func boolean(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

// toModel converts an account to the comparable model.
func (g *Connector) toModel(u *apiUser) model.TargetUser {
	t := model.TargetUser{ID: u.ID, Suspended: u.Suspended, Attrs: model.UserAttrs{}}
	t.Attrs[model.FieldPrimaryEmail] = model.NormalizeEmail(u.PrimaryEmail)
	if u.Name != nil {
		t.Attrs[model.FieldGivenName] = u.Name.GivenName
		t.Attrs[model.FieldFamilyName] = u.Name.FamilyName
	}
	t.Attrs[model.FieldOrgUnit] = u.OrgUnitPath
	if t.Attrs[model.FieldOrgUnit] == "" {
		t.Attrs[model.FieldOrgUnit] = "/"
	}
	t.Protected = u.IsAdmin || u.IsDelegatedAdmin || strings.EqualFold(u.PrimaryEmail, g.cfg.AdminSubject)
	for _, e := range u.ExternalIDs {
		switch {
		case str(e, "type") == "custom" && str(e, "customType") == g.cfg.Marker:
			t.Owner = str(e, "value")
		case str(e, "type") == "organization" && t.Attrs[model.FieldEmployeeID] == "":
			t.Attrs[model.FieldEmployeeID] = str(e, "value")
		}
	}
	if org := primaryOrg(u.Organizations); org != nil {
		t.Attrs[model.FieldTitle] = str(org, "title")
		t.Attrs[model.FieldDepartment] = str(org, "department")
	}
	for _, p := range u.Phones {
		switch str(p, "type") {
		case "work":
			if t.Attrs[model.FieldPhoneWork] == "" {
				t.Attrs[model.FieldPhoneWork] = str(p, "value")
			}
		case "mobile":
			if t.Attrs[model.FieldPhoneMobile] == "" {
				t.Attrs[model.FieldPhoneMobile] = str(p, "value")
			}
		}
	}
	t.Aliases = append(append([]string(nil), u.Aliases...), u.NonEditableAliases...)
	return t
}

func primaryOrg(orgs []map[string]any) map[string]any {
	for _, o := range orgs {
		if boolean(o, "primary") {
			return o
		}
	}
	if len(orgs) > 0 {
		return orgs[0]
	}
	return nil
}

// Snapshot implements connector.Connector.
func (g *Connector) Snapshot(ctx context.Context, groups bool) (*connector.Snapshot, error) {
	snap := &connector.Snapshot{}
	raw := map[string]*apiUser{}
	token := ""
	for {
		q := url.Values{"customer": {g.cfg.Customer}, "maxResults": {"500"}, "projection": {"basic"}, "showDeleted": {"false"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Users         []*apiUser `json:"users"`
			NextPageToken string     `json:"nextPageToken"`
		}
		if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/users", q, nil, &page); err != nil {
			return nil, fmt.Errorf("google: list users: %w", err)
		}
		for _, u := range page.Users {
			raw[u.ID] = u
			snap.Users = append(snap.Users, g.toModel(u))
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	g.mu.Lock()
	g.raw = raw
	g.mu.Unlock()
	if !groups {
		return snap, nil
	}
	token = ""
	for {
		q := url.Values{"customer": {g.cfg.Customer}, "maxResults": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Groups        []*apiGroup `json:"groups"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/groups", q, nil, &page); err != nil {
			return nil, fmt.Errorf("google: list groups: %w", err)
		}
		for _, gr := range page.Groups {
			tg := model.TargetGroup{ID: gr.ID, Email: model.NormalizeEmail(gr.Email), Name: gr.Name, Description: gr.Description,
				Aliases: append(append([]string(nil), gr.Aliases...), gr.NonEditableAliases...)}
			members, err := g.members(ctx, gr.ID)
			if err != nil {
				return nil, err
			}
			tg.Members = members
			snap.Groups = append(snap.Groups, tg)
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	return snap, nil
}

func (g *Connector) members(ctx context.Context, groupID string) ([]model.TargetMember, error) {
	var out []model.TargetMember
	token := ""
	for {
		q := url.Values{"maxResults": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Members       []apiMember `json:"members"`
			NextPageToken string      `json:"nextPageToken"`
		}
		if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/groups/"+url.PathEscape(groupID)+"/members", q, nil, &page); err != nil {
			return nil, fmt.Errorf("google: list members of %s: %w", groupID, err)
		}
		for _, m := range page.Members {
			tm := model.TargetMember{ID: m.ID, Email: model.NormalizeEmail(m.Email), Role: m.Role}
			switch m.Type {
			case "USER":
				tm.Kind = model.KindUser
			case "GROUP":
				tm.Kind = model.KindGroup
			}
			out = append(out, tm)
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		token = page.NextPageToken
	}
}

// randomPassword returns a 32-character password nobody knows: the
// account signs in through SSO or after an administrator reset.
func randomPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}

func (g *Connector) marker(sourceID string) map[string]any {
	return map[string]any{"type": "custom", "customType": g.cfg.Marker, "value": sourceID}
}

// mergeExternalIDs keeps foreign entries, sets the marker and (when
// managed) the employee ID.
func (g *Connector) mergeExternalIDs(cur []map[string]any, sourceID string, employee *string) []map[string]any {
	var out []map[string]any
	for _, e := range cur {
		if str(e, "type") == "custom" && str(e, "customType") == g.cfg.Marker {
			continue
		}
		if employee != nil && str(e, "type") == "organization" {
			continue
		}
		out = append(out, e)
	}
	if sourceID != "" {
		out = append(out, g.marker(sourceID))
	}
	if employee != nil && *employee != "" {
		out = append(out, map[string]any{"type": "organization", "value": *employee})
	}
	return out
}

// mergeOrganizations sets title and department on the primary entry (or
// the first one), keeping every other field and entry.
func mergeOrganizations(cur []map[string]any, attrs model.UserAttrs, title, dept bool) []map[string]any {
	target := -1
	for i, o := range cur {
		if boolean(o, "primary") {
			target = i
			break
		}
	}
	if target < 0 && len(cur) > 0 {
		target = 0
	}
	out := make([]map[string]any, 0, len(cur)+1)
	for _, o := range cur {
		c := map[string]any{}
		for k, v := range o {
			c[k] = v
		}
		out = append(out, c)
	}
	if target < 0 {
		out = append(out, map[string]any{"type": "work"})
		target = len(out) - 1
	}
	if title {
		out[target]["title"] = attrs[model.FieldTitle]
	}
	if dept {
		out[target]["department"] = attrs[model.FieldDepartment]
	}
	out[target]["primary"] = true
	return out
}

// mergePhones replaces the work and/or mobile entries.
func mergePhones(cur []map[string]any, attrs model.UserAttrs, work, mobile bool) []map[string]any {
	var out []map[string]any
	for _, p := range cur {
		t := str(p, "type")
		if (work && t == "work") || (mobile && t == "mobile") {
			continue
		}
		out = append(out, p)
	}
	if work && attrs[model.FieldPhoneWork] != "" {
		out = append(out, map[string]any{"type": "work", "value": attrs[model.FieldPhoneWork]})
	}
	if mobile && attrs[model.FieldPhoneMobile] != "" {
		out = append(out, map[string]any{"type": "mobile", "value": attrs[model.FieldPhoneMobile]})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// CreateUser implements connector.Connector.
func (g *Connector) CreateUser(ctx context.Context, sourceID string, attrs model.UserAttrs, suspended bool) (string, error) {
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"primaryEmail":              attrs[model.FieldPrimaryEmail],
		"name":                      apiName{GivenName: attrs[model.FieldGivenName], FamilyName: attrs[model.FieldFamilyName]},
		"password":                  pw,
		"changePasswordAtNextLogin": true,
		"orgUnitPath":               attrs[model.FieldOrgUnit],
		"suspended":                 suspended,
	}
	var emp *string
	if v, ok := attrs[model.FieldEmployeeID]; ok {
		emp = &v
	}
	body["externalIds"] = g.mergeExternalIDs(nil, sourceID, emp)
	_, hasTitle := attrs[model.FieldTitle]
	_, hasDept := attrs[model.FieldDepartment]
	if (hasTitle && attrs[model.FieldTitle] != "") || (hasDept && attrs[model.FieldDepartment] != "") {
		body["organizations"] = mergeOrganizations(nil, attrs, hasTitle, hasDept)
	}
	_, hasWork := attrs[model.FieldPhoneWork]
	_, hasMobile := attrs[model.FieldPhoneMobile]
	if phones := mergePhones(nil, attrs, hasWork, hasMobile); len(phones) > 0 {
		body["phones"] = phones
	}
	var created apiUser
	_, err = g.c.do(ctx, http.MethodPost, apiPrefix+"/users", nil, body, &created)
	if err != nil {
		if errors.Is(err, connector.ErrConflict) {
			// Our own earlier attempt (or an interrupted run) may have
			// created it: an account carrying our marker for this source
			// is the result, anything else is a real conflict.
			if u, gerr := g.GetUser(ctx, attrs[model.FieldPrimaryEmail]); gerr == nil && u.Owner == sourceID {
				return u.ID, nil
			}
		}
		return "", fmt.Errorf("google: create user %s: %w", attrs[model.FieldPrimaryEmail], err)
	}
	g.mu.Lock()
	g.raw[created.ID] = &created
	g.mu.Unlock()
	return created.ID, nil
}

func (g *Connector) rawUser(ctx context.Context, id string) (*apiUser, error) {
	g.mu.Lock()
	u, ok := g.raw[id]
	g.mu.Unlock()
	if ok {
		return u, nil
	}
	var fetched apiUser
	if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/users/"+url.PathEscape(id), url.Values{"projection": {"basic"}}, nil, &fetched); err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.raw[id] = &fetched
	g.mu.Unlock()
	return &fetched, nil
}

// UpdateUser implements connector.Connector.
func (g *Connector) UpdateUser(ctx context.Context, targetID, sourceID string, attrs model.UserAttrs, changes []plan.Change, claim bool) error {
	body := map[string]any{}
	changed := map[model.UserField]bool{}
	for _, c := range changes {
		changed[model.UserField(c.Field)] = true
	}
	if changed[model.FieldPrimaryEmail] {
		body["primaryEmail"] = attrs[model.FieldPrimaryEmail]
	}
	if changed[model.FieldGivenName] || changed[model.FieldFamilyName] {
		body["name"] = apiName{GivenName: attrs[model.FieldGivenName], FamilyName: attrs[model.FieldFamilyName]}
	}
	if changed[model.FieldOrgUnit] {
		body["orgUnitPath"] = attrs[model.FieldOrgUnit]
	}
	needRaw := claim || changed[model.FieldEmployeeID] || changed[model.FieldTitle] || changed[model.FieldDepartment] ||
		changed[model.FieldPhoneWork] || changed[model.FieldPhoneMobile]
	if needRaw {
		cur, err := g.rawUser(ctx, targetID)
		if err != nil {
			return fmt.Errorf("google: read user %s: %w", targetID, err)
		}
		if claim || changed[model.FieldEmployeeID] {
			var emp *string
			if changed[model.FieldEmployeeID] {
				v := attrs[model.FieldEmployeeID]
				emp = &v
			}
			owner := sourceID
			if !claim {
				owner = ownerOf(cur.ExternalIDs, g.cfg.Marker)
			}
			body["externalIds"] = g.mergeExternalIDs(cur.ExternalIDs, owner, emp)
		}
		if changed[model.FieldTitle] || changed[model.FieldDepartment] {
			body["organizations"] = mergeOrganizations(cur.Organizations, attrs, changed[model.FieldTitle], changed[model.FieldDepartment])
		}
		if changed[model.FieldPhoneWork] || changed[model.FieldPhoneMobile] {
			body["phones"] = mergePhones(cur.Phones, attrs, changed[model.FieldPhoneWork], changed[model.FieldPhoneMobile])
		}
	}
	if len(body) == 0 {
		return nil
	}
	var updated apiUser
	if _, err := g.c.do(ctx, http.MethodPatch, apiPrefix+"/users/"+url.PathEscape(targetID), nil, body, &updated); err != nil {
		return fmt.Errorf("google: update user %s: %w", targetID, err)
	}
	g.mu.Lock()
	if updated.ID != "" {
		g.raw[targetID] = &updated
	} else {
		delete(g.raw, targetID)
	}
	g.mu.Unlock()
	return nil
}

func ownerOf(ids []map[string]any, marker string) string {
	for _, e := range ids {
		if str(e, "type") == "custom" && str(e, "customType") == marker {
			return str(e, "value")
		}
	}
	return ""
}

// SetSuspended implements connector.Connector.
func (g *Connector) SetSuspended(ctx context.Context, targetID string, suspended bool) error {
	if _, err := g.c.do(ctx, http.MethodPatch, apiPrefix+"/users/"+url.PathEscape(targetID), nil,
		map[string]any{"suspended": suspended}, nil); err != nil {
		return fmt.Errorf("google: set suspended=%v on %s: %w", suspended, targetID, err)
	}
	return nil
}

// CreateGroup implements connector.Connector.
func (g *Connector) CreateGroup(ctx context.Context, spec plan.GroupSpec) (string, error) {
	var created apiGroup
	info, err := g.c.do(ctx, http.MethodPost, apiPrefix+"/groups", nil,
		apiGroup{Email: spec.Email, Name: spec.Name, Description: spec.Description}, &created)
	if err != nil {
		if errors.Is(err, connector.ErrConflict) && info.ambiguous {
			// An earlier attempt of this very call may have created it.
			var existing apiGroup
			if _, gerr := g.c.do(ctx, http.MethodGet, apiPrefix+"/groups/"+url.PathEscape(spec.Email), nil, nil, &existing); gerr == nil &&
				strings.EqualFold(existing.Email, spec.Email) && existing.Name == spec.Name {
				return existing.ID, nil
			}
		}
		return "", fmt.Errorf("google: create group %s: %w", spec.Email, err)
	}
	return created.ID, nil
}

// UpdateGroup implements connector.Connector.
func (g *Connector) UpdateGroup(ctx context.Context, targetID string, spec plan.GroupSpec) error {
	if _, err := g.c.do(ctx, http.MethodPatch, apiPrefix+"/groups/"+url.PathEscape(targetID), nil,
		apiGroup{Email: spec.Email, Name: spec.Name, Description: spec.Description}, nil); err != nil {
		return fmt.Errorf("google: update group %s: %w", spec.Email, err)
	}
	return nil
}

// AddMember implements connector.Connector.
func (g *Connector) AddMember(ctx context.Context, groupID string, kind model.Kind, memberID, memberEmail string) error {
	m := apiMember{Role: g.cfg.MemberRole}
	if memberID != "" {
		m.ID = memberID
	} else {
		m.Email = memberEmail
	}
	_, err := g.c.do(ctx, http.MethodPost, apiPrefix+"/groups/"+url.PathEscape(groupID)+"/members", nil, m, nil)
	if err != nil && errors.Is(err, connector.ErrConflict) {
		return nil // already a member
	}
	if err != nil {
		return fmt.Errorf("google: add %s %s to %s: %w", kind, memberEmail, groupID, err)
	}
	return nil
}

// RemoveMember implements connector.Connector.
func (g *Connector) RemoveMember(ctx context.Context, groupID, memberID, memberEmail string) error {
	key := memberID
	if key == "" {
		key = memberEmail
	}
	_, err := g.c.do(ctx, http.MethodDelete, apiPrefix+"/groups/"+url.PathEscape(groupID)+"/members/"+url.PathEscape(key), nil, nil, nil)
	if err != nil && errors.Is(err, connector.ErrNotFound) {
		// Already gone. (A missing group also answers 404; the next plan
		// reports that group as missing.)
		return nil
	}
	if err != nil {
		return fmt.Errorf("google: remove %s from %s: %w", memberEmail, groupID, err)
	}
	return nil
}

// GetUser implements connector.Connector.
func (g *Connector) GetUser(ctx context.Context, key string) (*model.TargetUser, error) {
	var u apiUser
	if _, err := g.c.do(ctx, http.MethodGet, apiPrefix+"/users/"+url.PathEscape(key), url.Values{"projection": {"basic"}}, nil, &u); err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.raw[u.ID] = &u
	g.mu.Unlock()
	t := g.toModel(&u)
	return &t, nil
}

// DeleteUser implements connector.Connector (manual delete command only).
func (g *Connector) DeleteUser(ctx context.Context, targetID string) error {
	if _, err := g.c.do(ctx, http.MethodDelete, apiPrefix+"/users/"+url.PathEscape(targetID), nil, nil, nil); err != nil {
		return fmt.Errorf("google: delete user %s: %w", targetID, err)
	}
	return nil
}
