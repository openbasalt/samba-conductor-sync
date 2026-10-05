// Package syncapi is the local management API of conductor-sync: the
// protocol between conductor's web interface (the only client) and
// `conductor-sync serve`. It holds only types, validation, framing and a
// client, so conductor can import it without the engine.
//
// Transport: a Unix stream socket (DefaultSocketPath), owned by the
// conductor-sync user, mode 0660 with a group the conductor user is in (or
// created by systemd socket activation). The server checks the peer with
// SO_PEERCRED on every connection and admits only the configured UIDs.
// Framing: one request and one response per connection, each one JSON
// object on one line, at most MaxMessageSize bytes. Requests name an
// allowlisted operation; parameters are decoded strictly (unknown fields
// rejected) and validated. Every request carries the acting AD user, which
// the server writes to its hash-chained audit log for every mutation.
//
// Secrets: the Google service account key (key.set), the AD bind password
// (secret.set, config.update, connection.test) and the webhook HMAC secret
// (secret.set) cross the socket in one direction only. They are never
// returned, logged or audited: results and the audit log carry their name
// and whether they are configured, never a value or a fingerprint. The
// self-service operations (account.go) carry a user's new target password
// once: chosen by the user in a request, or generated and returned once in
// a result; it is never stored, logged or audited either.
package syncapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// ProtocolVersion is bumped on incompatible changes (2: P5c, editable
// connection settings and write-only secrets; results are decoded
// strictly, so conductor and conductor-sync are upgraded together).
const ProtocolVersion = 2

// DefaultSocketPath is where `conductor-sync serve` listens.
const DefaultSocketPath = "/run/conductor-sync/api.sock"

// MaxMessageSize bounds one framed message (a page of a large plan fits
// easily; whole plans are never sent at once).
const MaxMessageSize = 4 << 20

// Op names an allowlisted operation.
type Op string

// Operations.
const (
	OpStatus         Op = "status"
	OpConfigGet      Op = "config.get"
	OpConfigValidate Op = "config.validate"
	OpConfigUpdate   Op = "config.update"
	OpConfigHistory  Op = "config.history"
	OpConfigExport   Op = "config.export"
	OpConfigVersion  Op = "config.version"
	OpConfigRollback Op = "config.rollback"
	OpKeySet         Op = "key.set"
	OpSecretSet      Op = "secret.set"
	OpSecretRemove   Op = "secret.remove"
	OpConnectionTest Op = "connection.test"
	OpMappingPreview Op = "mapping.preview"
	OpPlanStart      Op = "plan.start"
	OpApplyStart     Op = "apply.start"
	OpJobGet         Op = "job.get"
	OpRunsList       Op = "runs.list"
	OpRunGet         Op = "run.get"
	OpAuditVerify    Op = "audit.verify"
	// OpImportPlan reads the Google directory (read-only scopes, no write
	// to Google or AD) and returns the users and groups an administrator
	// may create in AD with conductor's "Import from Google Workspace".
	OpImportPlan Op = "import.plan"
)

// Mutating reports whether the operation changes state (configuration,
// key, runs, the target directory). Mutations are audited with the actor.
func (o Op) Mutating() bool {
	switch o {
	case OpConfigUpdate, OpConfigRollback, OpKeySet, OpSecretSet, OpSecretRemove, OpPlanStart, OpApplyStart,
		OpAccountActivate, OpAccountSetPassword:
		return true
	}
	return false
}

// Actor is the signed-in conductor user a request is made for.
type Actor struct {
	// User is the AD sAMAccountName.
	User string `json:"user"`
	SID  string `json:"sid"`
	// Session is an opaque identifier of the web session (not the cookie).
	Session string `json:"session"`
	IP      string `json:"ip,omitempty"`
}

// String renders the actor for the audit log.
func (a Actor) String() string {
	s := "conductor:" + a.User
	if a.IP != "" {
		s += "@" + a.IP
	}
	return s
}

// Request is one call.
type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Op      Op              `json:"op"`
	Actor   Actor           `json:"actor"`
	Params  json.RawMessage `json:"params,omitempty"`
	SentAt  time.Time       `json:"sent_at"`
}

// ErrorCode classifies a failed call.
type ErrorCode string

// Error codes.
const (
	CodeBadRequest  ErrorCode = "bad_request"
	CodeInvalid     ErrorCode = "invalid"   // validation failed; Details lists why
	CodeNotFound    ErrorCode = "not_found" // run, job or plan unknown
	CodeConflict    ErrorCode = "conflict"  // stale base version, plan changed
	CodeBusy        ErrorCode = "busy"      // a run is in progress
	CodeUnavailable ErrorCode = "unavailable"
	CodeFailed      ErrorCode = "failed"
	CodeForbidden   ErrorCode = "forbidden"
	CodeVersion     ErrorCode = "version"
)

// Error is the error part of a Response.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details []string  `json:"details,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("conductor-sync: %s: %s", e.Code, e.Message) }

// Response answers a Request with the same ID.
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Params is implemented by every parameter type.
type Params interface{ Validate() error }

// NoParams is used by operations without parameters.
type NoParams struct{}

// Validate implements Params.
func (NoParams) Validate() error { return nil }

// Allowlist maps each operation to a constructor of its parameter type.
var Allowlist = map[Op]func() Params{
	OpStatus:         func() Params { return &NoParams{} },
	OpConfigGet:      func() Params { return &NoParams{} },
	OpConfigValidate: func() Params { return &ConfigValidateParams{} },
	OpConfigUpdate:   func() Params { return &ConfigUpdateParams{} },
	OpConfigHistory:  func() Params { return &ConfigHistoryParams{} },
	OpConfigExport:   func() Params { return &NoParams{} },
	OpConfigVersion:  func() Params { return &ConfigVersionParams{} },
	OpConfigRollback: func() Params { return &ConfigRollbackParams{} },
	OpKeySet:         func() Params { return &KeySetParams{} },
	OpSecretSet:      func() Params { return &SecretSetParams{} },
	OpSecretRemove:   func() Params { return &SecretRemoveParams{} },
	OpConnectionTest: func() Params { return &ConnectionTestParams{} },
	OpMappingPreview: func() Params { return &MappingPreviewParams{} },
	OpPlanStart:      func() Params { return &NoParams{} },
	OpApplyStart:     func() Params { return &ApplyStartParams{} },
	OpJobGet:         func() Params { return &JobGetParams{} },
	OpRunsList:       func() Params { return &RunsListParams{} },
	OpRunGet:         func() Params { return &RunGetParams{} },
	OpAuditVerify:    func() Params { return &NoParams{} },
	OpImportPlan:     func() Params { return &ImportPlanParams{} },
	// Self-service (account.go).
	OpAccountStatus:      func() Params { return &AccountStatusParams{} },
	OpAccountActivate:    func() Params { return &AccountActivateParams{} },
	OpAccountSetPassword: func() Params { return &AccountSetPasswordParams{} },
}

var (
	idRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	userRE = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
	sidRE  = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,15}$`)
)

// NewRequest builds a validated request.
func NewRequest(id string, op Op, actor Actor, params Params) (Request, error) {
	if params == nil {
		params = NoParams{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return Request{}, err
	}
	req := Request{Version: ProtocolVersion, ID: id, Op: op, Actor: actor, Params: raw, SentAt: time.Now().UTC()}
	if _, err := req.Decode(); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Decode validates the envelope and decodes the typed parameters.
func (r Request) Decode() (Params, error) {
	if r.Version != ProtocolVersion {
		return nil, &Error{Code: CodeVersion, Message: fmt.Sprintf("protocol version %d, want %d", r.Version, ProtocolVersion)}
	}
	if !idRE.MatchString(r.ID) {
		return nil, &Error{Code: CodeBadRequest, Message: "invalid request id"}
	}
	if !userRE.MatchString(r.Actor.User) || r.Actor.Session == "" || len(r.Actor.Session) > 128 || len(r.Actor.IP) > 64 {
		return nil, &Error{Code: CodeBadRequest, Message: "the actor (user and session) is required"}
	}
	if !sidRE.MatchString(r.Actor.SID) {
		return nil, &Error{Code: CodeBadRequest, Message: "the actor SID is invalid"}
	}
	mk, ok := Allowlist[r.Op]
	if !ok {
		return nil, &Error{Code: CodeBadRequest, Message: fmt.Sprintf("operation %q is not allowlisted", r.Op)}
	}
	p := mk()
	params := r.Params
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: "params: " + err.Error()}
	}
	if dec.More() {
		return nil, &Error{Code: CodeBadRequest, Message: "params: trailing data"}
	}
	if err := p.Validate(); err != nil {
		return nil, &Error{Code: CodeBadRequest, Message: err.Error()}
	}
	return p, nil
}

// OKResponse builds a successful response.
func OKResponse(id string, result any) (Response, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{}, err
	}
	return Response{Version: ProtocolVersion, ID: id, OK: true, Result: raw}, nil
}

// ErrorResponse builds a failed response.
func ErrorResponse(id string, e *Error) Response {
	return Response{Version: ProtocolVersion, ID: id, Error: e}
}

// WriteMessage frames v as one JSON line.
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxMessageSize {
		return ErrTooLarge
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ErrTooLarge is returned for a message beyond MaxMessageSize.
var ErrTooLarge = errors.New("syncapi: message too large")

// ReadMessage reads one framed message into v (unknown fields rejected).
func ReadMessage(r *bufio.Reader, v any) error {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessageSize {
			return ErrTooLarge
		}
		if !isPrefix {
			break
		}
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---- parameters ----

// ConfigValidateParams checks settings without saving them.
type ConfigValidateParams struct {
	Settings Settings `json:"settings"`
}

// Validate implements Params.
func (ConfigValidateParams) Validate() error { return nil }

// ConfigUpdateParams saves new settings as a new version. BaseVersion must
// be the version the editor started from (optimistic concurrency).
//
// A change of the AD connection (realm, DCs, DNS servers, CA, bind user,
// authentication) is saved only after conductor-sync has signed in to AD
// with it; ADPassword (write only) replaces the stored bind password in
// the same transaction, for a new bind account. A change of the ownership
// marker needs MarkerConfirmation = MarkerConfirmation(new marker).
type ConfigUpdateParams struct {
	BaseVersion        int64    `json:"base_version"`
	Settings           Settings `json:"settings"`
	Comment            string   `json:"comment,omitempty"`
	ADPassword         string   `json:"ad_password,omitempty"`
	MarkerConfirmation string   `json:"marker_confirmation,omitempty"`
}

// Validate implements Params.
func (p ConfigUpdateParams) Validate() error {
	if p.BaseVersion < 0 {
		return errors.New("base_version must not be negative")
	}
	if err := validComment(p.Comment); err != nil {
		return err
	}
	if p.ADPassword != "" {
		if err := ValidateSecret(SecretADBindPassword, p.ADPassword); err != nil {
			return err
		}
	}
	if len(p.MarkerConfirmation) > 200 {
		return errors.New("marker_confirmation: at most 200 bytes")
	}
	return nil
}

func validComment(c string) error {
	if len(c) > 500 || strings.ContainsAny(c, "\x00\r\n") {
		return errors.New("comment: one line, at most 500 bytes")
	}
	return nil
}

// ConfigVersionParams reads one stored version with its settings.
type ConfigVersionParams struct {
	ID int64 `json:"id"`
}

// Validate implements Params.
func (p ConfigVersionParams) Validate() error {
	if p.ID <= 0 {
		return errors.New("id > 0")
	}
	return nil
}

// ConfigRollbackParams stores the settings of an earlier version as a new
// version (origin "rollback"). Secrets are not versioned and stay as they
// are. The same checks as an update apply (AD sign-in when the AD
// connection changes, MarkerConfirmation when the marker changes).
type ConfigRollbackParams struct {
	BaseVersion        int64  `json:"base_version"`
	Version            int64  `json:"version"`
	Comment            string `json:"comment,omitempty"`
	MarkerConfirmation string `json:"marker_confirmation,omitempty"`
}

// Validate implements Params.
func (p ConfigRollbackParams) Validate() error {
	if p.BaseVersion < 0 || p.Version <= 0 {
		return errors.New("base_version >= 0 and version > 0")
	}
	if len(p.MarkerConfirmation) > 200 {
		return errors.New("marker_confirmation: at most 200 bytes")
	}
	return validComment(p.Comment)
}

// ValidateSecret checks a secret value for name without revealing it in
// the error.
func ValidateSecret(name, value string) error {
	switch name {
	case SecretADBindPassword:
		if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("the AD bind password: 1-1024 bytes, one line")
		}
	case SecretWebhookSecret:
		if len(value) < minWebhookSecretLength || len(value) > 1024 {
			return fmt.Errorf("the webhook secret: %d-1024 bytes", minWebhookSecretLength)
		}
		for _, r := range value {
			if r < 0x21 || r == 0x7f {
				return errors.New("the webhook secret: printable characters without spaces")
			}
		}
	case SecretGoogleKey:
		return errors.New("the service account key is set with key.set")
	default:
		return fmt.Errorf("unknown secret %q", name)
	}
	return nil
}

// SecretSetParams stores (or replaces) a secret, encrypted at rest. The AD
// bind password is stored only after a successful sign-in to AD with it.
type SecretSetParams struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Validate implements Params.
func (p SecretSetParams) Validate() error {
	if len(p.Value) > maxSecretValue {
		return errors.New("value too large")
	}
	return ValidateSecret(p.Name, p.Value)
}

// SecretRemoveParams removes a stored secret (the configuration file's
// credential, if any, is used again).
type SecretRemoveParams struct {
	Name string `json:"name"`
}

// Validate implements Params.
func (p SecretRemoveParams) Validate() error {
	for _, n := range SecretNames {
		if p.Name == n {
			return nil
		}
	}
	return fmt.Errorf("unknown secret %q", p.Name)
}

// ConfigHistoryParams lists configuration versions, newest first.
type ConfigHistoryParams struct {
	Limit int `json:"limit,omitempty"`
}

// Validate implements Params.
func (p ConfigHistoryParams) Validate() error {
	if p.Limit < 0 || p.Limit > 500 {
		return errors.New("limit: 0-500")
	}
	return nil
}

// MaxKeySize bounds a service account key file.
const MaxKeySize = 16 << 10

// KeySetParams stores the Google service account key (write only).
type KeySetParams struct {
	KeyJSON string `json:"key_json"`
}

// Validate implements Params.
func (p KeySetParams) Validate() error {
	if p.KeyJSON == "" || len(p.KeyJSON) > MaxKeySize {
		return fmt.Errorf("key_json: 1-%d bytes", MaxKeySize)
	}
	return nil
}

// ConnectionTestParams tests AD and Google with the saved settings, or with
// a draft when Settings is set (the stored key is always the one used).
// ADPassword (write only, used for this test and never stored) replaces
// the bind password for the AD part.
type ConnectionTestParams struct {
	Settings   *Settings `json:"settings,omitempty"`
	ADPassword string    `json:"ad_password,omitempty"`
}

// Validate implements Params.
func (p ConnectionTestParams) Validate() error {
	if p.ADPassword != "" {
		return ValidateSecret(SecretADBindPassword, p.ADPassword)
	}
	return nil
}

// MappingPreviewParams renders the mapping of a draft (or the saved
// settings) for a sample of real AD users, without writing anything.
type MappingPreviewParams struct {
	Settings *Settings `json:"settings,omitempty"`
	// Query narrows the sample (logon name, name or e-mail contains).
	Query string `json:"query,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// Validate implements Params.
func (p MappingPreviewParams) Validate() error {
	if p.Limit < 0 || p.Limit > 100 {
		return errors.New("limit: 0-100")
	}
	if len(p.Query) > 64 || strings.ContainsAny(p.Query, "\x00\r\n") {
		return errors.New("query: at most 64 characters")
	}
	return nil
}

// ApplyStartParams starts an apply. A manual apply is bound to a reviewed
// plan: RunID and Digest of that plan (the fresh plan must match it). A
// scheduled-style run ("run now") takes neither and follows the timer's
// rules: binding limits, no override, first apply must have been manual.
type ApplyStartParams struct {
	RunID          int64  `json:"run_id,omitempty"`
	Digest         string `json:"digest,omitempty"`
	OverrideLimits bool   `json:"override_limits,omitempty"`
	Scheduled      bool   `json:"scheduled,omitempty"`
}

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate implements Params.
func (p ApplyStartParams) Validate() error {
	if p.Scheduled {
		if p.RunID != 0 || p.Digest != "" || p.OverrideLimits {
			return errors.New("a scheduled-style run takes no plan, digest or override")
		}
		return nil
	}
	if p.RunID <= 0 || !digestRE.MatchString(p.Digest) {
		return errors.New("a manual apply needs the run ID and the digest of the reviewed plan")
	}
	return nil
}

// JobGetParams reads a background job.
type JobGetParams struct {
	ID string `json:"id"`
}

// Validate implements Params.
func (p JobGetParams) Validate() error {
	if !idRE.MatchString(p.ID) {
		return errors.New("invalid job id")
	}
	return nil
}

// RunsListParams lists runs, newest first.
type RunsListParams struct {
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Status string `json:"status,omitempty"`
}

// Validate implements Params.
func (p RunsListParams) Validate() error {
	if p.Limit < 0 || p.Limit > 200 || p.Offset < 0 {
		return errors.New("limit 0-200, offset >= 0")
	}
	if p.Status != "" && !validStatus[p.Status] {
		return fmt.Errorf("unknown status %q", p.Status)
	}
	return nil
}

// RunGetParams reads one run with a page of its operations. Section picks
// the operations of one group (OpGroups); empty means all.
type RunGetParams struct {
	ID      int64  `json:"id"`
	Section string `json:"section,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	// FailedOnly lists only operations that failed or were skipped.
	FailedOnly bool `json:"failed_only,omitempty"`
}

// Validate implements Params.
func (p RunGetParams) Validate() error {
	if p.ID <= 0 || p.Offset < 0 || p.Limit < 0 || p.Limit > 500 {
		return errors.New("id > 0, offset >= 0, limit 0-500")
	}
	if p.Section != "" {
		if _, ok := sectionKinds[p.Section]; !ok {
			return fmt.Errorf("unknown section %q", p.Section)
		}
	}
	return nil
}

// Import limits: the most users and groups one import plan returns, and
// the most filter values of each kind.
const (
	MaxImportUsers   = 5000
	MaxImportGroups  = 1000
	maxImportFilters = 100
)

// ImportPlanParams select what import.plan returns. Every list is
// optional; the defaults leave out suspended accounts and administrators.
type ImportPlanParams struct {
	// OrgUnits keeps users whose org unit path is one of these ("/Sales");
	// with SubOrgUnits, also the org units below them. Empty: every org
	// unit.
	OrgUnits    []string `json:"org_units,omitempty"`
	SubOrgUnits bool     `json:"sub_org_units,omitempty"`
	// MemberOf keeps users that are members (nested membership counts) of
	// at least one of these Google groups (addresses). Every group named
	// must exist.
	MemberOf []string `json:"member_of,omitempty"`
	// IncludeSuspended and IncludeAdmins add suspended accounts and
	// Google administrators (both left out by default).
	IncludeSuspended bool `json:"include_suspended,omitempty"`
	IncludeAdmins    bool `json:"include_admins,omitempty"`
	// Groups adds Google groups to the plan: all of them, or only
	// GroupEmails (every one named must exist). SkipEmptyGroups leaves out
	// groups without any member in the plan.
	Groups          bool     `json:"groups,omitempty"`
	GroupEmails     []string `json:"group_emails,omitempty"`
	SkipEmptyGroups bool     `json:"skip_empty_groups,omitempty"`
	// MaxUsers and MaxGroups bound the plan (0: the defaults, 500 and
	// 200). Objects beyond them are counted as skipped ("limit").
	MaxUsers  int `json:"max_users,omitempty"`
	MaxGroups int `json:"max_groups,omitempty"`
}

var (
	importEmailRE = regexp.MustCompile(`^[^@\s\x00-\x1f]{1,64}@[A-Za-z0-9.-]{1,253}$`)
	orgUnitRE     = regexp.MustCompile(`^/[^\x00-\x1f]{0,511}$`)
)

// Validate implements Params.
func (p ImportPlanParams) Validate() error {
	if p.MaxUsers < 0 || p.MaxUsers > MaxImportUsers || p.MaxGroups < 0 || p.MaxGroups > MaxImportGroups {
		return fmt.Errorf("max_users 0-%d, max_groups 0-%d", MaxImportUsers, MaxImportGroups)
	}
	if len(p.OrgUnits) > maxImportFilters || len(p.MemberOf) > maxImportFilters || len(p.GroupEmails) > maxImportFilters {
		return fmt.Errorf("at most %d org units, groups or group addresses", maxImportFilters)
	}
	for _, ou := range p.OrgUnits {
		if !orgUnitRE.MatchString(ou) {
			return fmt.Errorf("org unit %q: a path that starts with /", ou)
		}
	}
	for _, list := range [][]string{p.MemberOf, p.GroupEmails} {
		for _, e := range list {
			if !importEmailRE.MatchString(e) {
				return fmt.Errorf("%q is not a group address", e)
			}
		}
	}
	if len(p.GroupEmails) > 0 && !p.Groups {
		return errors.New("group_emails needs groups")
	}
	return nil
}
