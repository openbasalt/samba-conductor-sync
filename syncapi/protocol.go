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
// Secrets: the only secret that crosses the socket is the Google service
// account key, in one direction (key.set). It is never returned.
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

// ProtocolVersion is bumped on incompatible changes.
const ProtocolVersion = 1

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
	OpKeySet         Op = "key.set"
	OpConnectionTest Op = "connection.test"
	OpMappingPreview Op = "mapping.preview"
	OpPlanStart      Op = "plan.start"
	OpApplyStart     Op = "apply.start"
	OpJobGet         Op = "job.get"
	OpRunsList       Op = "runs.list"
	OpRunGet         Op = "run.get"
	OpAuditVerify    Op = "audit.verify"
)

// Mutating reports whether the operation changes state (configuration,
// key, runs, the target directory). Mutations are audited with the actor.
func (o Op) Mutating() bool {
	switch o {
	case OpConfigUpdate, OpKeySet, OpPlanStart, OpApplyStart:
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
	OpKeySet:         func() Params { return &KeySetParams{} },
	OpConnectionTest: func() Params { return &ConnectionTestParams{} },
	OpMappingPreview: func() Params { return &MappingPreviewParams{} },
	OpPlanStart:      func() Params { return &NoParams{} },
	OpApplyStart:     func() Params { return &ApplyStartParams{} },
	OpJobGet:         func() Params { return &JobGetParams{} },
	OpRunsList:       func() Params { return &RunsListParams{} },
	OpRunGet:         func() Params { return &RunGetParams{} },
	OpAuditVerify:    func() Params { return &NoParams{} },
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
type ConfigUpdateParams struct {
	BaseVersion int64    `json:"base_version"`
	Settings    Settings `json:"settings"`
	Comment     string   `json:"comment,omitempty"`
}

// Validate implements Params.
func (p ConfigUpdateParams) Validate() error {
	if p.BaseVersion < 0 {
		return errors.New("base_version must not be negative")
	}
	if len(p.Comment) > 500 || strings.ContainsAny(p.Comment, "\x00\r\n") {
		return errors.New("comment: one line, at most 500 bytes")
	}
	return nil
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
type ConnectionTestParams struct {
	Settings *Settings `json:"settings,omitempty"`
}

// Validate implements Params.
func (ConnectionTestParams) Validate() error { return nil }

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
