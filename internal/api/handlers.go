package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/gimport"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Handle serves one decoded request (the socket layer has checked the
// peer). Exported for tests.
func (s *Server) Handle(ctx context.Context, req syncapi.Request) syncapi.Response {
	params, err := req.Decode()
	if err != nil {
		var e *syncapi.Error
		if !errors.As(err, &e) {
			e = &syncapi.Error{Code: syncapi.CodeBadRequest, Message: err.Error()}
		}
		return syncapi.ErrorResponse(req.ID, e)
	}
	result, err := s.dispatch(ctx, req, params)
	if err != nil {
		e := toAPIError(err)
		// The g2a operations audit their own failures (without personal
		// data).
		if req.Op.Mutating() && req.Op != syncapi.OpG2APlan && req.Op != syncapi.OpG2AConfirm {
			s.audit(ctx, req, "api."+string(req.Op), "", e.Message, store.ResultFailed)
		}
		s.log.Info("request failed", "op", req.Op, "actor", req.Actor.User, "code", e.Code, "err", e.Message)
		return syncapi.ErrorResponse(req.ID, e)
	}
	resp, err := syncapi.OKResponse(req.ID, result)
	if err != nil {
		return syncapi.ErrorResponse(req.ID, &syncapi.Error{Code: syncapi.CodeFailed, Message: err.Error()})
	}
	return resp
}

// errInvalid carries validation messages.
type errInvalid struct {
	msg     string
	details []string
}

func (e errInvalid) Error() string { return e.msg }

func toAPIError(err error) *syncapi.Error {
	var e *syncapi.Error
	var inv errInvalid
	switch {
	case errors.As(err, &e):
		return e
	case errors.As(err, &inv):
		return &syncapi.Error{Code: syncapi.CodeInvalid, Message: inv.msg, Details: inv.details}
	case errors.Is(err, store.ErrStaleVersion):
		return &syncapi.Error{Code: syncapi.CodeConflict, Message: err.Error()}
	case errors.Is(err, store.ErrLocked):
		return &syncapi.Error{Code: syncapi.CodeBusy, Message: err.Error()}
	case errors.Is(err, context.DeadlineExceeded):
		return &syncapi.Error{Code: syncapi.CodeUnavailable, Message: "timed out"}
	}
	return &syncapi.Error{Code: syncapi.CodeFailed, Message: err.Error()}
}

// actorName is how API actors appear in conductor-sync's audit log and
// runs.
func actorName(a syncapi.Actor) string { return a.String() }

func (s *Server) audit(ctx context.Context, req syncapi.Request, action, target, detail, result string) {
	d := map[string]any{"sid": req.Actor.SID, "session": req.Actor.Session, "request": req.ID}
	if detail != "" {
		d["detail"] = detail
	}
	b, _ := json.Marshal(d)
	if _, err := s.rt.Store.AppendAudit(context.WithoutCancel(ctx), store.AuditEvent{Actor: actorName(req.Actor), Action: action,
		Target: target, Detail: string(b), Result: result}); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}

func (s *Server) dispatch(ctx context.Context, req syncapi.Request, params syncapi.Params) (any, error) {
	switch p := params.(type) {
	case *syncapi.ConfigValidateParams:
		return s.configValidate(ctx, p)
	case *syncapi.ConfigUpdateParams:
		return s.configUpdate(ctx, req, p)
	case *syncapi.ConfigHistoryParams:
		return s.configHistory(ctx, p)
	case *syncapi.KeySetParams:
		return s.keySet(ctx, req, p)
	case *syncapi.ConfigVersionParams:
		return s.configVersion(ctx, p)
	case *syncapi.ConfigRollbackParams:
		return s.configRollback(ctx, req, p)
	case *syncapi.SecretSetParams:
		return s.secretSet(ctx, req, p)
	case *syncapi.SecretRemoveParams:
		return s.secretRemove(ctx, req, p)
	case *syncapi.ConnectionTestParams:
		return s.connectionTest(ctx, p)
	case *syncapi.MappingPreviewParams:
		return s.mappingPreview(ctx, p)
	case *syncapi.ApplyStartParams:
		return s.applyStart(ctx, req, p)
	case *syncapi.JobGetParams:
		return s.jobGet(ctx, p)
	case *syncapi.RunsListParams:
		return s.runsList(ctx, p)
	case *syncapi.RunGetParams:
		return s.runGet(ctx, p)
	case *syncapi.ImportPlanParams:
		return s.importPlan(ctx, req, p)
	case *syncapi.AccountStatusParams:
		return s.accountStatus(ctx, req, p)
	case *syncapi.AccountActivateParams:
		return s.accountActivate(ctx, req, p)
	case *syncapi.AccountSetPasswordParams:
		return s.accountSetPassword(ctx, req, p)
	case *syncapi.G2APlanParams:
		return s.g2aPlan(ctx, req, p)
	case *syncapi.G2AConfirmParams:
		return s.g2aConfirm(ctx, req, p)
	}
	switch req.Op {
	case syncapi.OpStatus:
		return s.status(ctx)
	case syncapi.OpConfigGet:
		return s.configGet(ctx)
	case syncapi.OpConfigExport:
		return s.configExport(ctx)
	case syncapi.OpPlanStart:
		return s.planStart(ctx, req)
	case syncapi.OpAuditVerify:
		return s.auditVerify(ctx)
	}
	return nil, &syncapi.Error{Code: syncapi.CodeBadRequest, Message: "unhandled operation"}
}

// ---- status ----

func (s *Server) status(ctx context.Context) (*syncapi.Status, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	st := s.rt.Store
	out := &syncapi.Status{Version: s.version, Mode: cfg.Mode, Connector: cfg.Connector, Scheduler: "timer",
		ScheduleInterval: cfg.Schedule.Interval.Duration.String(), ConfigVersion: cfg.SettingsVersion, Job: s.jobs.current()}
	if cfg.Schedule.InProcess {
		out.Scheduler = "in-process"
	}
	if out.FirstManualApply, err = st.Meta(ctx, "first_manual_apply"); err != nil {
		return nil, err
	}
	if out.Links.Users, out.Links.SuspendedBySync, out.Links.Groups, err = st.LinkCounts(ctx, cfg.Connector); err != nil {
		return nil, err
	}
	if r, err := st.LastRun(ctx, cfg.Connector, "", ""); err != nil {
		return nil, err
	} else if r != nil {
		out.LastRun = s.runView(ctx, r)
	}
	if r, err := st.LastRun(ctx, cfg.Connector, "apply", ""); err != nil {
		return nil, err
	} else if r != nil {
		out.LastApply = s.runView(ctx, r)
	}
	var after int64
	if r, err := st.LastRunWithStatus(ctx, cfg.Connector, "apply", store.StatusApplied, store.StatusNothing); err != nil {
		return nil, err
	} else if r != nil {
		out.LastSuccess = s.runView(ctx, r)
		after = r.ID
	}
	blocked, err := st.BlockedSince(ctx, cfg.Connector, after)
	if err != nil {
		return nil, err
	}
	for i := range blocked {
		out.OpenBlocked = append(out.OpenBlocked, *s.runView(ctx, &blocked[i]))
	}
	out.NextScheduled = s.nextRun(ctx, cfg)
	inflight, err := st.InFlight(ctx, cfg.Connector)
	if err != nil {
		return nil, err
	}
	out.InFlight = len(inflight)
	v, err := st.VerifyAudit(ctx)
	if err != nil {
		return nil, err
	}
	out.Audit = syncapi.AuditState{Intact: v.BrokenAt == 0, Rows: v.Rows, BrokenAt: v.BrokenAt, Reason: v.Reason, LastHash: v.LastHash}
	if cv, err := st.LatestConfig(ctx); err != nil {
		return nil, err
	} else if cv != nil {
		out.ConfigAt, out.ConfigBy = cv.At, cv.Actor
	}
	if out.Key, err = s.rt.KeyInfo(ctx, cfg); err != nil {
		return nil, err
	}
	out.Ready = out.Key != nil && cfg.Google.AdminSubject != ""
	return out, nil
}

// nextRun estimates the next scheduled run: the in-process scheduler knows
// it; under the systemd timer it is the last scheduled run plus the
// interval (zero when no scheduled run has happened yet).
func (s *Server) nextRun(ctx context.Context, cfg *config.Config) time.Time {
	if cfg.Schedule.InProcess {
		s.schedMu.Lock()
		defer s.schedMu.Unlock()
		return s.nextScheduled
	}
	r, err := s.rt.Store.LastRun(ctx, cfg.Connector, "apply", "scheduled")
	if err != nil || r == nil {
		return time.Time{}
	}
	end := r.FinishedAt
	if end.IsZero() {
		end = r.StartedAt
	}
	return end.Add(cfg.Schedule.Interval.Duration)
}

// runView converts a stored run (summary decoded).
func (s *Server) runView(ctx context.Context, r *store.Run) *syncapi.Run {
	out := &syncapi.Run{ID: r.ID, Action: r.Action, Trigger: r.Trigger, Actor: r.Actor, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		Status: r.Status, Digest: r.PlanDigest, SourceUsers: r.SourceUsers, SourceGroups: r.SourceGroups, OpsTotal: r.OpsTotal,
		OpsDone: r.OpsDone, OpsFailed: r.OpsFailed, Error: r.Error}
	var sum engine.Summary
	if json.Unmarshal(r.Summary, &sum) == nil {
		if len(sum.Counts) > 0 {
			out.Counts = map[string]int{}
			for k, v := range sum.Counts {
				out.Counts[string(k)] = v
			}
		}
		for _, v := range sum.Violations {
			out.Violations = append(out.Violations, syncapi.Violation{Limit: v.Limit, Value: v.Value, Max: v.Max})
		}
		out.Warnings, out.Errors, out.Skipped = sum.Warnings, sum.Errors, sum.Skipped
	}
	out.HasPlan, _ = s.rt.Store.HasPlan(ctx, r.ID)
	return out
}

// ---- configuration ----

func (s *Server) hostInfo(cfg *config.Config) syncapi.HostInfo {
	return syncapi.HostInfo{ConfigPath: cfg.Path, Realm: cfg.Source.Realm, DCs: cfg.Source.DCs, BindUser: cfg.Source.BindUser,
		Auth: cfg.Source.Auth, StateDir: cfg.StateDir, Marker: cfg.Google.Marker, APIBaseURL: cfg.Google.APIBaseURL,
		AlertWebhook: cfg.Alert.WebhookURL != "", ConnectionStored: cfg.ConnectionStored,
		PasswordCredential: cfg.Source.PasswordCredential, KeyCredential: cfg.Google.KeyCredential,
		WebhookSecretCredential: cfg.Alert.WebhookSecretCredential}
}

func (s *Server) configGet(ctx context.Context) (*syncapi.ConfigView, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	v := &syncapi.ConfigView{Version: cfg.SettingsVersion, Settings: config.SettingsOf(cfg), Host: s.hostInfo(cfg)}
	if v.Secrets, err = s.rt.Secrets(ctx, cfg); err != nil {
		return nil, err
	}
	if cv, err := s.rt.Store.LatestConfig(ctx); err != nil {
		return nil, err
	} else if cv != nil {
		v.UpdatedAt, v.UpdatedBy = cv.At, cv.Actor
	}
	return v, nil
}

func (s *Server) configValidate(ctx context.Context, p *syncapi.ConfigValidateParams) (*syncapi.ConfigValidateResult, error) {
	cur, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	next, err := s.rt.File.Overlay(p.Settings, 0)
	if err != nil {
		return &syncapi.ConfigValidateResult{Valid: false, Errors: config.ErrorList(err)}, nil
	}
	return &syncapi.ConfigValidateResult{Valid: true, Changes: syncapi.DiffSettings(config.SettingsOf(cur), config.SettingsOf(next))}, nil
}

func (s *Server) configUpdate(ctx context.Context, req syncapi.Request, p *syncapi.ConfigUpdateParams) (*syncapi.ConfigUpdateResult, error) {
	return s.saveVersion(ctx, req, versionChange{base: p.BaseVersion, settings: p.Settings, comment: p.Comment, origin: app.OriginAPI,
		markerConfirmation: p.MarkerConfirmation, adPassword: p.ADPassword, action: "config.update"})
}

// versionChange is a new settings version to validate and store.
type versionChange struct {
	base               int64
	settings           syncapi.Settings
	comment, origin    string
	markerConfirmation string
	// adPassword replaces the stored AD bind password with the version
	// (write only; never audited).
	adPassword string
	action     string
	// note is a first audit line (a rollback names its source version).
	note string
}

// errMarker refuses a marker change without its typed confirmation.
var errMarker = &syncapi.Error{Code: syncapi.CodeInvalid, Message: "the ownership marker changes: the typed confirmation is required",
	Details: []string{"changing google.marker orphans the accounts marked with the previous value"}}

// saveVersion validates a change against the settings in force, checks
// what a web session must not do silently (the marker without its typed
// confirmation, an AD connection conductor-sync cannot sign in with), then
// stores the version (and the bind password, in the same transaction).
func (s *Server) saveVersion(ctx context.Context, req syncapi.Request, vc versionChange) (*syncapi.ConfigUpdateResult, error) {
	cur, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	if vc.base != cur.SettingsVersion {
		return nil, store.ErrStaleVersion
	}
	next, err := s.rt.File.Overlay(vc.settings, 0)
	if err != nil {
		return nil, errInvalid{msg: "the settings are not valid", details: config.ErrorList(err)}
	}
	if next.Google.Marker != cur.Google.Marker && vc.markerConfirmation != syncapi.MarkerConfirmation(next.Google.Marker) {
		return nil, errMarker
	}
	if config.ADConnectionChanged(cur, next) || vc.adPassword != "" {
		test := next
		if vc.adPassword != "" {
			test = next.WithADPassword(vc.adPassword)
		}
		if _, err := s.rt.NewSource(test).Ping(ctx); err != nil {
			return nil, errInvalid{msg: "conductor-sync could not sign in to AD with the new connection settings; nothing was saved",
				details: []string{"could not sign in to AD with the new connection settings (nothing was saved): " + err.Error()}}
		}
	}
	var secrets []app.SealedSecret
	if vc.adPassword != "" {
		secrets = append(secrets, app.SealedSecret{APIName: syncapi.SecretADBindPassword, Value: []byte(vc.adPassword)})
	}
	id, changes, err := s.rt.SaveSettingsWith(ctx, vc.base, vc.settings, actorName(req.Actor), vc.origin, vc.comment, secrets)
	if err != nil {
		if errors.Is(err, store.ErrStaleVersion) {
			return nil, err
		}
		return nil, errInvalid{msg: "the settings are not valid", details: config.ErrorList(err)}
	}
	res := &syncapi.ConfigUpdateResult{Version: id, Changes: changes}
	if len(changes) > 0 || len(secrets) > 0 {
		var lines []string
		if vc.note != "" {
			lines = append(lines, vc.note)
		}
		if vc.comment != "" {
			lines = append(lines, vc.comment)
		}
		for _, c := range changes {
			lines = append(lines, c.String())
		}
		// Secrets: the name and that it changed, never a value or a
		// fingerprint.
		for _, sec := range secrets {
			lines = append(lines, "secret "+sec.APIName+": replaced")
			res.Secrets = append(res.Secrets, sec.APIName)
		}
		s.audit(ctx, req, vc.action, fmt.Sprintf("version %d", id), strings.Join(lines, "\n"), store.ResultOK)
	}
	return res, nil
}

func (s *Server) configVersion(ctx context.Context, p *syncapi.ConfigVersionParams) (*syncapi.ConfigVersionDetail, error) {
	v, settings, err := s.rt.VersionSettings(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: fmt.Sprintf("no settings version %d", p.ID)}
	}
	out := &syncapi.ConfigVersionDetail{ConfigVersion: syncapi.ConfigVersion{ID: v.ID, At: v.At, Actor: v.Actor, Origin: v.Origin, Comment: v.Comment},
		Settings: *settings}
	_ = json.Unmarshal(v.Changes, &out.Changes)
	return out, nil
}

// configRollback stores the settings of an earlier version as the newest
// one. Secrets are not versioned and are left as they are.
func (s *Server) configRollback(ctx context.Context, req syncapi.Request, p *syncapi.ConfigRollbackParams) (*syncapi.ConfigUpdateResult, error) {
	v, settings, err := s.rt.VersionSettings(ctx, p.Version)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: fmt.Sprintf("no settings version %d", p.Version)}
	}
	return s.saveVersion(ctx, req, versionChange{base: p.BaseVersion, settings: *settings, comment: p.Comment, origin: app.OriginRollback,
		markerConfirmation: p.MarkerConfirmation, action: "config.rollback", note: fmt.Sprintf("rollback to version %d", p.Version)})
}

func (s *Server) configHistory(ctx context.Context, p *syncapi.ConfigHistoryParams) ([]syncapi.ConfigVersion, error) {
	rows, err := s.rt.Store.ConfigHistory(ctx, p.Limit)
	if err != nil {
		return nil, err
	}
	out := []syncapi.ConfigVersion{}
	for _, r := range rows {
		v := syncapi.ConfigVersion{ID: r.ID, At: r.At, Actor: r.Actor, Origin: r.Origin, Comment: r.Comment}
		_ = json.Unmarshal(r.Changes, &v.Changes)
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) configExport(ctx context.Context) (*syncapi.ConfigExport, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	t, err := config.Export(cfg)
	if err != nil {
		return nil, err
	}
	return &syncapi.ConfigExport{TOML: t}, nil
}

// ---- secrets (write only) ----

func (s *Server) secretInfo(ctx context.Context, name string) (*syncapi.SecretInfo, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	all, err := s.rt.Secrets(ctx, cfg)
	if err != nil {
		return nil, err
	}
	for _, i := range all {
		if i.Name == name {
			return &i, nil
		}
	}
	return &syncapi.SecretInfo{Name: name}, nil
}

// secretSet stores a secret. The AD bind password is stored only after
// conductor-sync signed in to AD with it (the connection in force). The
// audit names the secret and says it changed: no value, no fingerprint.
func (s *Server) secretSet(ctx context.Context, req syncapi.Request, p *syncapi.SecretSetParams) (*syncapi.SecretInfo, error) {
	before, err := s.secretInfo(ctx, p.Name)
	if err != nil {
		return nil, err
	}
	if p.Name == syncapi.SecretADBindPassword {
		cfg, err := s.rt.Effective(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := s.rt.NewSource(cfg.WithADPassword(p.Value)).Ping(ctx); err != nil {
			return nil, errInvalid{msg: "conductor-sync could not sign in to AD with this password; nothing was saved",
				details: []string{"could not sign in to AD with this password (nothing was saved): " + err.Error()}}
		}
	}
	if err := s.rt.SetSecret(ctx, p.Name, []byte(p.Value), actorName(req.Actor)); err != nil {
		return nil, errInvalid{msg: err.Error()}
	}
	what := "set"
	if before.Source == "database" {
		what = "replaced"
	}
	s.audit(ctx, req, "secret.set", p.Name, "secret "+p.Name+": "+what, store.ResultOK)
	return s.secretInfo(ctx, p.Name)
}

// secretRemove deletes a stored secret: the credential file named in the
// configuration (if any) is used again.
func (s *Server) secretRemove(ctx context.Context, req syncapi.Request, p *syncapi.SecretRemoveParams) (*syncapi.SecretInfo, error) {
	existed, err := s.rt.RemoveSecret(ctx, p.Name)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: "no stored value for " + p.Name}
	}
	s.audit(ctx, req, "secret.remove", p.Name, "secret "+p.Name+": removed", store.ResultOK)
	return s.secretInfo(ctx, p.Name)
}

// ---- key ----

func (s *Server) keySet(ctx context.Context, req syncapi.Request, p *syncapi.KeySetParams) (*syncapi.KeyInfo, error) {
	info, err := s.rt.SetKey(ctx, []byte(p.KeyJSON), actorName(req.Actor))
	if err != nil {
		return nil, errInvalid{msg: err.Error()}
	}
	// Only the identity of the key is audited, never the key.
	s.audit(ctx, req, "key.set", "google service account", fmt.Sprintf("client_email %s, key_id %s", info.ClientEmail, info.KeyID), store.ResultOK)
	return info, nil
}

// ---- connection test and mapping preview (read-only) ----

func (s *Server) draft(ctx context.Context, settings *syncapi.Settings) (*config.Config, error) {
	if settings == nil {
		return s.rt.Effective(ctx)
	}
	c, err := s.rt.File.Overlay(*settings, 0)
	if err != nil {
		return nil, errInvalid{msg: "the settings are not valid", details: config.ErrorList(err)}
	}
	return c, nil
}

func scopeGroups(in []model.ScopeGroup) []syncapi.ScopeGroup {
	out := make([]syncapi.ScopeGroup, len(in))
	for i, g := range in {
		out[i] = syncapi.ScopeGroup{Role: g.Role, Ref: g.Ref, Found: g.Found, DN: g.DN, Name: g.Name, SID: g.SID, Members: g.Members,
			Target: g.Target, Priority: g.Priority}
	}
	return out
}

func (s *Server) connectionTest(ctx context.Context, p *syncapi.ConnectionTestParams) (*syncapi.TestResult, error) {
	cfg, err := s.draft(ctx, p.Settings)
	if err != nil {
		return nil, err
	}
	if p.ADPassword != "" {
		cfg = cfg.WithADPassword(p.ADPassword)
	}
	out := &syncapi.TestResult{}
	detail, groups, err := s.rt.NewSource(cfg).Check(ctx)
	out.Groups = scopeGroups(groups)
	out.AD = syncapi.Check{OK: err == nil, Detail: detail}
	if err != nil {
		out.AD.Error = err.Error()
	}
	// Google: a token with the read-only scopes and a read of the admin
	// subject prove the key, the domain-wide delegation and the subject.
	conn, err := s.rt.Connector(ctx, cfg, false)
	if err == nil {
		var u *model.TargetUser
		if u, err = conn.GetUser(ctx, cfg.Google.AdminSubject); err == nil {
			role := "not an administrator"
			if u.Protected {
				role = "administrator"
			}
			out.Google = syncapi.Check{OK: true, Detail: fmt.Sprintf("token issued; %s found (%s)", cfg.Google.AdminSubject, role)}
		}
	}
	if err != nil {
		out.Google = syncapi.Check{OK: false, Error: err.Error()}
	}
	return out, nil
}

func (s *Server) mappingPreview(ctx context.Context, p *syncapi.MappingPreviewParams) (*syncapi.PreviewResult, error) {
	cfg, err := s.draft(ctx, p.Settings)
	if err != nil {
		return nil, err
	}
	users, groups, err := s.rt.NewSource(cfg).Preview(ctx, p.Query, p.Limit)
	if err != nil {
		return nil, err
	}
	out := &syncapi.PreviewResult{Users: []syncapi.PreviewUser{}, Groups: scopeGroups(groups)}
	for _, u := range users {
		out.Users = append(out.Users, syncapi.PreviewUser{Account: u.Account, DN: u.DN, Enabled: u.Enabled, InScope: u.InScope,
			OutReason: u.OutReason, Email: u.Email, GivenName: u.GivenName, FamilyName: u.FamilyName, OrgUnit: u.OU,
			Placement: u.Placement, Error: u.Error})
	}
	return out, nil
}

// ---- plan and apply jobs ----

func (s *Server) busy(cur *syncapi.Job) error {
	return &syncapi.Error{Code: syncapi.CodeBusy, Message: fmt.Sprintf("a %s is already running (job %s)", cur.Kind, cur.ID)}
}

func (s *Server) planStart(ctx context.Context, req syncapi.Request) (*syncapi.JobStarted, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	actor := actorName(req.Actor)
	job, ok := s.jobs.start(s.base, "plan", actor, s.now, func(ctx context.Context, setRun func(int64)) (string, error) {
		eng, err := s.rt.Engine(ctx, cfg, actor, io.Discard)
		if err != nil {
			return "", err
		}
		eng.OnRun = setRun
		if _, err := eng.Plan(ctx, "manual"); err != nil {
			return store.StatusFailed, err
		}
		return store.StatusPlanned, nil
	})
	if !ok {
		return nil, s.busy(job)
	}
	s.audit(ctx, req, "api.plan.start", "job "+job.ID, "", store.ResultInfo)
	return &syncapi.JobStarted{Job: *job}, nil
}

func (s *Server) applyStart(ctx context.Context, req syncapi.Request, p *syncapi.ApplyStartParams) (*syncapi.JobStarted, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	opt := engine.ApplyOptions{Scheduled: p.Scheduled}
	kind := "scheduled"
	detail := "run now with the scheduled rules (binding limits)"
	if !p.Scheduled {
		kind = "apply"
		r, err := s.rt.Store.GetRun(ctx, p.RunID)
		if err != nil {
			return nil, err
		}
		pl, err := s.rt.Store.LoadPlan(ctx, p.RunID)
		if err != nil {
			return nil, err
		}
		if r == nil || pl == nil {
			return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: fmt.Sprintf("run %d has no recorded plan", p.RunID)}
		}
		if pl.Digest != p.Digest {
			return nil, &syncapi.Error{Code: syncapi.CodeConflict, Message: "the digest does not match the plan of that run"}
		}
		if cfg.Mode != engine.ModeApply {
			return nil, &syncapi.Error{Code: syncapi.CodeConflict, Message: "mode is dry-run; switch to apply first"}
		}
		opt.ExpectDigest, opt.OverrideLimits, opt.Yes = p.Digest, p.OverrideLimits, true
		opt.Note = fmt.Sprintf("reviewed plan of run %d; requested by %s", p.RunID, actorName(req.Actor))
		if r.Status == store.StatusBlocked {
			opt.Note = fmt.Sprintf("overrides blocked run %d; requested by %s", p.RunID, actorName(req.Actor))
		}
		detail = fmt.Sprintf("plan of run %d, digest %s, override_limits %v", p.RunID, p.Digest, p.OverrideLimits)
	}
	actor := actorName(req.Actor)
	job, ok := s.jobs.start(s.base, kind, actor, s.now, func(ctx context.Context, setRun func(int64)) (string, error) {
		eng, err := s.rt.Engine(ctx, cfg, actor, io.Discard)
		if err != nil {
			return "", err
		}
		eng.OnRun = setRun
		res, err := eng.Apply(ctx, opt)
		status := ""
		if res != nil {
			status = res.Status
		}
		return status, err
	})
	if !ok {
		return nil, s.busy(job)
	}
	s.audit(ctx, req, "api.apply.start", "job "+job.ID, detail, store.ResultInfo)
	return &syncapi.JobStarted{Job: *job}, nil
}

func (s *Server) jobGet(ctx context.Context, p *syncapi.JobGetParams) (*syncapi.Job, error) {
	j, ok := s.jobs.get(p.ID)
	if !ok {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: "unknown job (the server may have restarted)"}
	}
	if j.RunID != 0 && (j.Kind == "apply" || j.Kind == "scheduled") {
		if counts, err := s.rt.Store.OpCounts(ctx, j.RunID); err == nil {
			for st, n := range counts {
				j.Progress.Total += n
				switch st {
				case store.OpDone:
					j.Progress.Done += n
				case store.OpFailed:
					j.Progress.Failed += n
				case store.OpSkipped:
					j.Progress.Skipped += n
				}
			}
		}
	}
	return &j, nil
}

// ---- runs ----

func (s *Server) runsList(ctx context.Context, p *syncapi.RunsListParams) (*syncapi.RunsList, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	limit := p.Limit
	if limit == 0 {
		limit = 25
	}
	runs, total, err := s.rt.Store.ListRuns(ctx, cfg.Connector, p.Status, p.Offset, limit)
	if err != nil {
		return nil, err
	}
	out := &syncapi.RunsList{Runs: []syncapi.Run{}, Total: total}
	for i := range runs {
		out.Runs = append(out.Runs, *s.runView(ctx, &runs[i]))
	}
	return out, nil
}

func (s *Server) runGet(ctx context.Context, p *syncapi.RunGetParams) (*syncapi.RunDetail, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	r, err := s.rt.Store.GetRun(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if r == nil || r.Connector != cfg.Connector {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: fmt.Sprintf("no run %d", p.ID)}
	}
	out := &syncapi.RunDetail{Run: *s.runView(ctx, r), Ops: []syncapi.PlanOp{}}
	if r.Action == store.RunActionG2A {
		return s.g2aRunGet(ctx, out, p)
	}
	pl, err := s.rt.Store.LoadPlan(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if pl == nil {
		return out, nil
	}
	out.HasPlan, out.Digest, out.ManagedUsers, out.Writes = true, pl.Digest, pl.ManagedUsers, pl.Writes()
	out.Counts, out.Sections = map[string]int{}, map[string]int{}
	for k, v := range pl.Counts() {
		out.Counts[string(k)] = v
		out.Sections[syncapi.SectionOf(string(k))] += v
	}
	prev := 0
	if last, err := s.rt.Store.LastRunWithStatus(ctx, cfg.Connector, "apply", store.StatusApplied, store.StatusPartial, store.StatusNothing); err == nil && last != nil && last.ID < r.ID {
		prev = last.SourceUsers
	}
	for _, row := range cfg.Limits.Rows(pl, prev) {
		out.Limits = append(out.Limits, syncapi.LimitRow{Limit: row.Limit, Value: row.Value, Max: row.Max, Exceeded: row.Exceeded})
		if row.Exceeded {
			out.Override = true
		}
	}
	for _, w := range pl.Warnings {
		out.Warnings = append(out.Warnings, syncapi.Warning{Code: w.Code, Key: w.Key, Message: w.Message})
	}
	for _, w := range pl.Errors {
		out.Errors = append(out.Errors, syncapi.Warning{Code: w.Code, Key: w.Key, Message: w.Message})
	}
	for _, sk := range pl.Skipped {
		out.Skipped = append(out.Skipped, syncapi.Skipped{DN: sk.DN, Reason: sk.Reason})
	}
	out.Groups = scopeGroups(pl.Scope)
	// Journal state (applies).
	var journal map[int][2]string
	if r.Action == "apply" {
		if journal, err = s.rt.Store.JournalStatus(ctx, r.ID); err != nil {
			return nil, err
		}
	}
	kinds := map[string]bool{}
	for _, k := range syncapi.SectionKinds(p.Section) {
		kinds[k] = true
	}
	limit := p.Limit
	if limit == 0 {
		limit = 100
	}
	for seq, o := range pl.Ops {
		if p.Section != "" && !kinds[string(o.Kind)] {
			continue
		}
		op := planOp(seq, o)
		if j, ok := journal[seq]; ok {
			op.Status, op.Error = j[0], j[1]
		}
		if p.FailedOnly && op.Status != store.OpFailed && op.Status != store.OpSkipped {
			continue
		}
		out.OpsMatching++
		if out.OpsMatching > p.Offset && len(out.Ops) < limit {
			out.Ops = append(out.Ops, op)
		}
	}
	// Can this plan be applied by hand now?
	latest, err := s.rt.Store.LatestPlanRun(ctx, cfg.Connector)
	if err != nil {
		return nil, err
	}
	switch {
	case pl.Empty():
		out.NotApply = "empty"
	case r.Action == "activate":
		// A self-service activation: one user's create, applied when the
		// user asked for it; never applied again from here.
		out.NotApply = "self-service"
	case cfg.Mode != engine.ModeApply:
		out.NotApply = "dry-run"
	case latest != r.ID:
		out.NotApply = "superseded"
	case r.Action == "apply" && r.Status != store.StatusBlocked && r.Status != store.StatusDryRun && r.Status != store.StatusPlanned:
		out.NotApply = "applied"
	case s.jobs.current() != nil:
		out.NotApply = "busy"
	default:
		out.Applicable = true
		out.Confirmation = syncapi.Confirmation(pl.Digest, out.Override)
	}
	return out, nil
}

func planOp(seq int, o plan.Op) syncapi.PlanOp {
	op := syncapi.PlanOp{Seq: seq, Kind: string(o.Kind), Key: o.Key, Reason: o.Reason, Suspend: o.Suspend}
	for _, c := range o.Changes {
		op.Changes = append(op.Changes, syncapi.FieldChange{Field: c.Field, Old: c.Old, New: c.New})
	}
	if o.Kind == plan.UserCreate && len(o.Attrs) > 0 {
		op.Attrs = map[string]string{}
		for k, v := range o.Attrs {
			op.Attrs[string(k)] = v
		}
	}
	if o.Group != nil {
		op.GroupName = o.Group.Name
	}
	if o.Member != nil {
		op.MemberKind, op.MemberEmail = string(o.Member.Kind), o.Member.MemberEmail
	}
	return op
}

// ---- import from Google (read-only) ----

// importPlan reads the Google directory with the read-only scopes and
// returns what conductor may create in AD. It writes nothing anywhere (no
// run, no plan, no Google request other than reads); the read itself is
// audited with the actor, since it returns directory data.
func (s *Server) importPlan(ctx context.Context, req syncapi.Request, p *syncapi.ImportPlanParams) (*syncapi.ImportPlan, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	pl, err := s.rt.ImportPlan(ctx, cfg, *p)
	if err != nil {
		s.audit(ctx, req, "api.import.plan", "google", app.ImportSummary(*p, nil)+"; "+err.Error(), store.ResultFailed)
		if errors.Is(err, connector.ErrAuth) || errors.Is(err, app.ErrNoKey) {
			return nil, &syncapi.Error{Code: syncapi.CodeUnavailable, Message: err.Error()}
		}
		if errors.Is(err, gimport.ErrGroupNotFound) {
			return nil, errInvalid{msg: "a group named in the filters does not exist in Google", details: []string{err.Error()}}
		}
		return nil, err
	}
	// One answer must fit in a message.
	if b, err := json.Marshal(pl); err != nil {
		return nil, err
	} else if len(b) > syncapi.MaxMessageSize-64<<10 {
		return nil, errInvalid{msg: "the import plan is too large for one answer",
			details: []string{"narrow the filters (org units, groups) or lower max_users and max_groups"}}
	}
	s.audit(ctx, req, "api.import.plan", "google", app.ImportSummary(*p, pl), store.ResultInfo)
	return pl, nil
}

// ---- self-service (the actor's own account) ----

// accountEngine builds the engine for a self-service call on target.
func (s *Server) accountEngine(ctx context.Context, req syncapi.Request, target string) (*engine.Engine, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	if target != "" && target != cfg.Connector {
		return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: fmt.Sprintf("no target %q", target)}
	}
	return s.rt.Engine(ctx, cfg, actorName(req.Actor), nil)
}

// selfServiceErr maps the engine's self-service refusals: the reason code
// travels as the first detail, for the client to translate.
func selfServiceErr(err error) error {
	var se *engine.SelfServiceError
	switch {
	case errors.As(err, &se):
		return &syncapi.Error{Code: syncapi.CodeForbidden, Message: se.Message, Details: []string{se.Reason}}
	case errors.Is(err, engine.ErrRateLimited):
		return &syncapi.Error{Code: syncapi.CodeRateLimited, Message: err.Error()}
	case errors.Is(err, connector.ErrAuth) || errors.Is(err, app.ErrNoKey) || errors.Is(err, connector.ErrRateLimited):
		return &syncapi.Error{Code: syncapi.CodeUnavailable, Message: err.Error()}
	}
	return err
}

func (s *Server) accountStatus(ctx context.Context, req syncapi.Request, p *syncapi.AccountStatusParams) (*syncapi.AccountStatus, error) {
	eng, err := s.accountEngine(ctx, req, p.Target)
	if err != nil {
		return nil, err
	}
	a, err := eng.AccountStatus(ctx, req.Actor.SID)
	if err != nil {
		return nil, selfServiceErr(err)
	}
	return &syncapi.AccountStatus{Targets: []syncapi.TargetAccount{*a}}, nil
}

// accountActivate creates the actor's account now. The generated password
// (if any) is in the result only: never in the audit or the log.
func (s *Server) accountActivate(ctx context.Context, req syncapi.Request, p *syncapi.AccountActivateParams) (*syncapi.AccountActionResult, error) {
	eng, err := s.accountEngine(ctx, req, p.Target)
	if err != nil {
		return nil, err
	}
	res, err := eng.Activate(ctx, req.Actor.SID, p.PasswordChoice)
	if err != nil {
		return nil, selfServiceErr(err)
	}
	s.audit(ctx, req, "api.account.activate", p.Target, fmt.Sprintf("account %s created; password %s; %d warnings", res.Account.Address, p.Mode,
		len(res.Warnings)), store.ResultOK)
	return res, nil
}

// accountSetPassword sets a new password on the actor's linked account.
func (s *Server) accountSetPassword(ctx context.Context, req syncapi.Request, p *syncapi.AccountSetPasswordParams) (*syncapi.AccountActionResult, error) {
	eng, err := s.accountEngine(ctx, req, p.Target)
	if err != nil {
		return nil, err
	}
	res, err := eng.SetPassword(ctx, req.Actor.SID, p.PasswordChoice)
	if err != nil {
		return nil, selfServiceErr(err)
	}
	s.audit(ctx, req, "api.account.set_password", p.Target, fmt.Sprintf("account %s (%s); password %s", res.Account.Address, res.Account.Origin, p.Mode),
		store.ResultOK)
	return res, nil
}

func (s *Server) auditVerify(ctx context.Context) (*syncapi.AuditState, error) {
	v, err := s.rt.Store.VerifyAudit(ctx)
	if err != nil {
		return nil, err
	}
	return &syncapi.AuditState{Intact: v.BrokenAt == 0, Rows: v.Rows, BrokenAt: v.BrokenAt, Reason: v.Reason, LastHash: v.LastHash}, nil
}

// ---- in-process scheduler ----

// RunScheduler runs scheduled applies every schedule.interval (read from
// the effective configuration before each wait) until ctx ends. Used only
// with schedule.in_process; the systemd timer is the default scheduler.
func (s *Server) RunScheduler(ctx context.Context) {
	for {
		cfg, err := s.rt.Effective(ctx)
		interval := 15 * time.Minute
		if err == nil {
			interval = cfg.Schedule.Interval.Duration
		}
		next := s.now().Add(interval)
		s.schedMu.Lock()
		s.nextScheduled = next
		s.schedMu.Unlock()
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		cfg, err = s.rt.Effective(ctx)
		if err != nil {
			s.log.Error("scheduled run: configuration", "err", err)
			continue
		}
		if key, err := s.rt.KeyInfo(ctx, cfg); err != nil || key == nil {
			// Not set up yet (no service account key): nothing to plan,
			// and no failed run every interval until it is.
			s.log.Info("scheduled run skipped: no Google service account key yet")
			continue
		}
		job, ok := s.jobs.start(s.base, "scheduled", "scheduler", s.now, func(ctx context.Context, setRun func(int64)) (string, error) {
			eng, err := s.rt.Engine(ctx, cfg, "scheduler", nil)
			if err != nil {
				return "", err
			}
			eng.OnRun = setRun
			res, err := eng.Apply(ctx, engine.ApplyOptions{Scheduled: true})
			status := ""
			if res != nil {
				status = res.Status
			}
			if err != nil && !errors.Is(err, engine.ErrDryRun) {
				s.log.Warn("scheduled run", "status", status, "err", err)
			}
			if errors.Is(err, engine.ErrDryRun) {
				err = nil
			}
			return status, err
		})
		if !ok {
			s.log.Info("scheduled run skipped: another run is in progress", "job", job.ID)
		}
	}
}
