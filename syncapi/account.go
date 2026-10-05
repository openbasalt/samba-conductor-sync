package syncapi

import (
	"errors"
	"regexp"
	"strings"
)

// Self-service: a signed-in user's own accounts on the target directories
// (conductor's "Connected accounts"). conductor calls these operations only
// on the user's explicit action, never from a schedule, and always for the
// actor of the request: conductor-sync resolves the AD user by Actor.SID,
// so a request can never name another user.
//
// What a target supports is declared by its connector (Capabilities); a
// client renders only that. Nothing here is specific to one target.
//
// Passwords cross the socket at most once in each direction: a password the
// user chose (AccountActivateParams, AccountSetPasswordParams) and a
// generated one (AccountActionResult.Password), sent to the target once and
// never stored, logged or audited by conductor-sync.

// Self-service operations.
const (
	// OpAccountStatus returns the actor's account on every target (or one).
	OpAccountStatus Op = "account.status"
	// OpAccountActivate creates the actor's account on a target now
	// (on-demand provisioning), with the mapping, scope and safety checks of
	// a sync run, and returns the initial password when it was generated.
	OpAccountActivate Op = "account.activate"
	// OpAccountSetPassword sets a new password on the actor's linked
	// account (generated and returned once, or chosen by the user).
	OpAccountSetPassword Op = "account.set_password"
)

// CodeRateLimited: too many self-service actions in the last hour (per user
// or per target). Clients that predate it show it as a generic failure.
const CodeRateLimited ErrorCode = "rate_limited"

// Password modes of the self-service actions.
const (
	// PasswordGenerate: conductor-sync generates a random password, sends
	// it to the target and returns it once in the result.
	PasswordGenerate = "generate"
	// PasswordChosen: the user typed the password (allowed only when the
	// target's policy says so); it is validated against the target's rules
	// and never returned.
	PasswordChosen = "chosen"
)

// MaxChosenPassword bounds a typed password crossing the socket (targets
// have their own, lower, limits in PasswordRules).
const MaxChosenPassword = 1024

var targetRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// PasswordChoice is how the new password of an action is made.
type PasswordChoice struct {
	Mode string `json:"mode"`
	// Password is the user's own password (mode chosen only). Write only.
	Password string `json:"password,omitempty"`
}

func (c PasswordChoice) validate() error {
	switch c.Mode {
	case PasswordGenerate:
		if c.Password != "" {
			return errors.New("a generated password takes no password")
		}
	case PasswordChosen:
		if c.Password == "" || len(c.Password) > MaxChosenPassword || strings.ContainsAny(c.Password, "\x00\r\n") {
			return errors.New("the chosen password: 1-1024 bytes, one line")
		}
	default:
		return errors.New(`mode: "generate" or "chosen"`)
	}
	return nil
}

// AccountStatusParams selects one target ("" = every target).
type AccountStatusParams struct {
	Target string `json:"target,omitempty"`
}

// Validate implements Params.
func (p AccountStatusParams) Validate() error {
	if p.Target != "" && !targetRE.MatchString(p.Target) {
		return errors.New("invalid target")
	}
	return nil
}

// AccountActivateParams activates the actor's account on a target.
type AccountActivateParams struct {
	Target string `json:"target"`
	PasswordChoice
}

// Validate implements Params.
func (p AccountActivateParams) Validate() error {
	if !targetRE.MatchString(p.Target) {
		return errors.New("invalid target")
	}
	return p.PasswordChoice.validate()
}

// AccountSetPasswordParams sets a new password on the actor's account.
type AccountSetPasswordParams struct {
	Target string `json:"target"`
	PasswordChoice
}

// Validate implements Params.
func (p AccountSetPasswordParams) Validate() error {
	if !targetRE.MatchString(p.Target) {
		return errors.New("invalid target")
	}
	return p.PasswordChoice.validate()
}

// Capabilities are the optional self-service features a target's connector
// declares. A client shows only what is declared.
type Capabilities struct {
	// OnDemandCreate: an account can be created for one user on request.
	OnDemandCreate bool `json:"on_demand_create"`
	// SetPassword: a password can be set on an account.
	SetPassword bool `json:"set_password"`
	// PasswordRules: the target publishes the rules of a password.
	PasswordRules bool `json:"password_rules"`
	// Status: one account's state can be read.
	Status bool `json:"status"`
}

// PasswordRules are what a password must satisfy on a target (the
// connector's own limits, raised by the self-service policy).
type PasswordRules struct {
	MinLength int `json:"min_length"`
	MaxLength int `json:"max_length"`
	// PrintableASCII: letters, digits, punctuation and spaces of ASCII only.
	PrintableASCII bool `json:"printable_ascii,omitempty"`
	// NoEdgeSpaces: no space at the start or the end.
	NoEdgeSpaces bool `json:"no_edge_spaces,omitempty"`
}

// Account states.
const (
	// AccountActive: linked and not suspended.
	AccountActive = "active"
	// AccountSuspended: linked and suspended on the target.
	AccountSuspended = "suspended"
	// AccountNotActivated: eligible, waiting for the user to activate it
	// (activation self-service).
	AccountNotActivated = "not-activated"
	// AccountPendingSync: eligible; the next sync run creates or links it.
	AccountPendingSync = "pending-sync"
	// AccountNotEligible: the user has no account there and cannot get one
	// (Reason says why).
	AccountNotEligible = "not-eligible"
	// AccountUnknown: the state could not be read (Reason says why).
	AccountUnknown = "unknown"
)

// Account origins.
const (
	OriginCreated = "created" // the sync created the account
	OriginAdopted = "adopted" // the account existed and was adopted by address
)

// Reason codes of a state or of an action that is not allowed. Clients
// translate known codes and show unknown ones as a generic sentence.
const (
	ReasonOutOfScope      = "out-of-scope"        // the AD user is not in the sync scope
	ReasonDisabled        = "disabled"            // the AD user is disabled (or expired)
	ReasonNoAddress       = "no-address"          // the mapping renders no valid address
	ReasonMappingError    = "mapping-error"       // a per-user mapping error (org unit)
	ReasonAddressTaken    = "address-taken"       // another account has the address
	ReasonExistingAccount = "existing-account"    // an account with the address exists; the next run links it
	ReasonDryRun          = "dry-run"             // the sync is in dry-run mode: nothing is written
	ReasonNotSupported    = "not-supported"       // the target does not support the action
	ReasonActivationAuto  = "activation-auto"     // accounts are created by the sync runs
	ReasonResetOff        = "reset-off"           // password reset is off for this target
	ReasonAdopted         = "adopted"             // the account was adopted; resets are not allowed for adopted accounts
	ReasonAdmin           = "admin"               // a target administrator (or the sync's own subject): never
	ReasonNotOwned        = "not-owned"           // the account does not carry the sync's marker for this user
	ReasonSuspended       = "suspended"           // the account is suspended
	ReasonNotLinked       = "not-linked"          // the user has no linked account
	ReasonAlreadyActive   = "already-active"      // the account exists already
	ReasonChosenOff       = "chosen-password-off" // typed passwords are not allowed here
	ReasonPasswordRules   = "password-rules"      // the typed password breaks the rules
	ReasonTargetRefused   = "target-refused"      // the target refused the password (its own policy)
	ReasonUnavailable     = "unavailable"         // the target or AD could not be reached
)

// TargetAccount is the actor's account on one target.
type TargetAccount struct {
	// Target is the connector name ("google"); Title is its display name.
	Target       string       `json:"target"`
	Title        string       `json:"title"`
	Capabilities Capabilities `json:"capabilities"`
	State        string       `json:"state"`
	// Reason explains a not-eligible or unknown state.
	Reason string `json:"reason,omitempty"`
	// Address is the account's address on the target (or the one it would
	// get).
	Address string `json:"address,omitempty"`
	// Origin is created or adopted (linked accounts only).
	Origin string `json:"origin,omitempty"`
	// CanActivate and CanSetPassword say whether the action is allowed now;
	// ActivateReason and PasswordReason say why not (reason codes).
	CanActivate    bool   `json:"can_activate"`
	ActivateReason string `json:"activate_reason,omitempty"`
	CanSetPassword bool   `json:"can_set_password"`
	PasswordReason string `json:"password_reason,omitempty"`
	// ChosenPassword: the user may type their own password.
	ChosenPassword bool          `json:"chosen_password"`
	Rules          PasswordRules `json:"rules"`
	// ActionsLeft is how many self-service actions the user has left in
	// the current hour on this target.
	ActionsLeft int `json:"actions_left"`
}

// AccountStatus is the result of account.status.
type AccountStatus struct {
	Targets []TargetAccount `json:"targets"`
}

// AccountActionResult answers account.activate and account.set_password.
type AccountActionResult struct {
	Account TargetAccount `json:"account"`
	// Password is the generated password, returned once (mode generate
	// only). It is not stored anywhere: show it to the user and drop it.
	Password string `json:"password,omitempty"`
	// Warnings are non-fatal problems (for example a group membership that
	// could not be added after the account was created).
	Warnings []string `json:"warnings,omitempty"`
}
