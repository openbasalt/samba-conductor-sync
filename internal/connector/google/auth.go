package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
)

// Directory API scopes. Planning reads with the read-only scopes; only
// apply (and the manual delete) asks for the write scopes. Both sets must
// be authorized for the service account's client ID in the Admin console
// (domain-wide delegation).
var (
	ReadScopes = []string{
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.group.readonly",
	}
	WriteScopes = []string{
		"https://www.googleapis.com/auth/admin.directory.user",
		"https://www.googleapis.com/auth/admin.directory.group",
	}
)

// DefaultTokenURL is Google's OAuth 2.0 token endpoint.
const DefaultTokenURL = "https://oauth2.googleapis.com/token"

// ServiceAccountKey is the subset of a service account JSON key file that
// is used. The private key never leaves this struct.
type ServiceAccountKey struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`

	key *rsa.PrivateKey
}

// ParseServiceAccountKey decodes a JSON key file.
func ParseServiceAccountKey(b []byte) (*ServiceAccountKey, error) {
	var k ServiceAccountKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, errors.New("google: the service account key is not valid JSON")
	}
	if k.Type != "service_account" || k.ClientEmail == "" || k.PrivateKey == "" {
		return nil, errors.New("google: the key is not a service account key (type, client_email, private_key)")
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, errors.New("google: the service account private key is not PEM")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("google: unsupported private key type %q", block.Type)
	}
	if err != nil {
		return nil, errors.New("google: cannot parse the service account private key")
	}
	rk, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("google: the service account key is not RSA")
	}
	k.key = rk
	k.PrivateKey = "" // keep only the parsed key
	return &k, nil
}

// NewTestKey builds a key around an RSA key (tests and the fake API).
func NewTestKey(clientEmail string, rk *rsa.PrivateKey, tokenURI string) *ServiceAccountKey {
	return &ServiceAccountKey{Type: "service_account", ClientEmail: clientEmail, PrivateKeyID: "test", TokenURI: tokenURI, key: rk}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion builds the RS256-signed JWT for the JWT bearer grant (RFC
// 7523) with domain-wide delegation: sub is the admin being impersonated.
func (k *ServiceAccountKey) assertion(subject, aud string, scopes []string, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if k.PrivateKeyID != "" {
		header["kid"] = k.PrivateKeyID
	}
	claims := map[string]any{
		"iss":   k.ClientEmail,
		"sub":   subject,
		"scope": strings.Join(scopes, " "),
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signing := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// tokenSource fetches and caches an access token for one subject and scope
// set.
type tokenSource struct {
	key      *ServiceAccountKey
	subject  string
	scopes   []string
	tokenURL string
	hc       *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (t *tokenSource) invalidate() {
	t.mu.Lock()
	t.token = ""
	t.mu.Unlock()
}

// get returns a valid token, fetching a new one a minute before expiry.
func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if t.token != "" && now.Before(t.expires.Add(-time.Minute)) {
		return t.token, nil
	}
	jwt, err := t.key.assertion(t.subject, t.tokenURL, t.scopes, now)
	if err != nil {
		return "", fmt.Errorf("%w: sign assertion: %v", connector.ErrAuth, err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("google: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		// The error text from Google names the problem (e.g.
		// unauthorized_client: the scopes are not delegated); it carries
		// no secret.
		return "", fmt.Errorf("%w: token endpoint returned %d %s %s", connector.ErrAuth, resp.StatusCode, clip(e.Error, 80), clip(e.Description, 200))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("%w: malformed token response", connector.ErrAuth)
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 3600
	}
	t.token = tok.AccessToken
	t.expires = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	return t.token, nil
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
