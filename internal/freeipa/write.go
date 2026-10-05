package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Write operations are carried out only through explicitly supported directory
// commands.

// UserSpec describes an account to create.
type UserSpec struct {
	UID       string
	FirstName string
	LastName  string
	Email     string
	Shell     string
	// Groups are the groups the account is to belong to after creation.
	Groups []string
	// SSHKeys are public keys. A private key never reaches the system.
	SSHKeys []string
}

// Validate checks that the description of the account holds together.
func (s UserSpec) Validate() error {
	if !userNamePattern.MatchString(s.UID) {
		return fmt.Errorf("invalid account name %q", s.UID)
	}
	if strings.TrimSpace(s.LastName) == "" {
		return fmt.Errorf("an account requires a surname")
	}
	for _, group := range s.Groups {
		if !groupNamePattern.MatchString(group) {
			return fmt.Errorf("invalid group name %q", group)
		}
	}
	for _, key := range s.SSHKeys {
		if err := validateSSHPublicKey(key); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser creates an account in the directory and returns its state after creation.
func (c *Client) CreateUser(ctx context.Context, spec UserSpec) (*User, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	options := map[string]any{
		"givenname": firstNonEmpty(spec.FirstName, spec.UID),
		"sn":        spec.LastName,
	}
	if spec.Email != "" {
		options["mail"] = []string{spec.Email}
	}
	if spec.Shell != "" {
		options["loginshell"] = spec.Shell
	}
	if len(spec.SSHKeys) > 0 {
		options["ipasshpubkey"] = spec.SSHKeys
	}

	if _, err := c.call(ctx, "user_add", []string{spec.UID}, options); err != nil {
		return nil, fmt.Errorf("creating the account %s: %w", spec.UID, err)
	}
	c.invalidate()
	return c.ShowUser(ctx, spec.UID)
}

// SetUserEnabled enables or locks an account.
func (c *Client) SetUserEnabled(ctx context.Context, uid string, enabled bool) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	method := "user_disable"
	if enabled {
		method = "user_enable"
	}
	if _, err := c.call(ctx, method, []string{uid}, nil); err != nil {
		// The directory reports an error also when the account is already in
		// the wanted state; that is not a failure of the operation.
		if strings.Contains(err.Error(), "already") {
			c.invalidate()
			return nil
		}
		return fmt.Errorf("changing the state of the account %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// AddGroupMembers adds accounts to a group.
func (c *Client) AddGroupMembers(ctx context.Context, group string, users []string) error {
	return c.changeGroupMembers(ctx, "group_add_member", group, users)
}

// RemoveGroupMembers removes accounts from a group.
func (c *Client) RemoveGroupMembers(ctx context.Context, group string, users []string) error {
	return c.changeGroupMembers(ctx, "group_remove_member", group, users)
}

// PartialChange says which accounts the directory took and which it refused.
// A batch that half succeeded is not a failure to retry whole: the accounts
// that moved have to have their sessions ended, and the cache is stale whatever
// the verdict - so the names travel with the error rather than being folded
// into its text.
type PartialChange struct {
	// Method is the directory call that was made, and Group the group it was
	// made on.
	Method string
	Group  string
	// Applied are the accounts the directory moved.
	Applied []string
	// Refused maps an account to the reason the directory gave.
	Refused map[string]string
}

func (p *PartialChange) Error() string {
	refused := make([]string, 0, len(p.Refused))
	for name, reason := range p.Refused {
		refused = append(refused, name+": "+reason)
	}
	sort.Strings(refused)
	return fmt.Sprintf("the membership of %s changed for %d of %d accounts; refused %s",
		p.Group, len(p.Applied), len(p.Applied)+len(p.Refused), strings.Join(refused, "; "))
}

// UncertainChange says a membership change went out and its outcome is not
// known: the directory did not answer, or it answered in a shape that names no
// account. Every account the batch named may have moved, so they travel with
// the error - an outcome nobody confirmed must not read as an outcome of none.
type UncertainChange struct {
	Method string
	Group  string
	// Users are the accounts the batch named, each of which may have moved.
	Users []string
	Err   error
}

func (u *UncertainChange) Error() string {
	return fmt.Sprintf("it is not known whether the membership of %s changed for %s: %v",
		u.Group, strings.Join(u.Users, ", "), u.Err)
}

func (u *UncertainChange) Unwrap() error { return u.Err }

func (c *Client) changeGroupMembers(ctx context.Context, method, group string, users []string) error {
	if !groupNamePattern.MatchString(group) {
		return fmt.Errorf("invalid group name %q", group)
	}
	if len(users) == 0 {
		return fmt.Errorf("no accounts to change the membership of")
	}
	for _, user := range users {
		if !userNamePattern.MatchString(user) {
			return fmt.Errorf("invalid account name %q", user)
		}
	}

	result, err := c.call(ctx, method, []string{group}, map[string]any{"user": users})
	if err != nil {
		var refusal *DirectoryError
		if errors.As(err, &refusal) && refusal.Permanent() {
			// The directory read the command and turned it down, so the
			// membership stands as it stood.
			return fmt.Errorf("changing the membership of the group %s: %w", group, err)
		}
		// The command went out and no verdict came back. The cache goes, because
		// the directory may well have applied it, and the accounts travel with
		// the error so their sessions end on the chance that they moved.
		c.invalidate()
		return &UncertainChange{Method: method, Group: group, Users: users, Err: err}
	}

	// The directory returns a list of failures instead of an error when some of
	// the accounts were not added. The cache is invalidated first and whatever
	// the verdict: a batch that half succeeded moved accounts, and leaving the
	// cache alone made the panel read the batch as unchanged - so the sessions
	// of the accounts that did move were never ended, and somebody removed
	// from a group went on working with the scope they had.
	c.invalidate()

	var decoded struct {
		Failed map[string]map[string][]any `json:"failed"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		// An answer in a shape this adapter does not read says nothing about
		// which accounts moved, and nothing is not "none of them".
		return &UncertainChange{Method: method, Group: group, Users: users,
			Err: fmt.Errorf("the answer of the directory does not read: %w", err)}
	}
	refused := map[string]string{}
	var unnamed []string
	for _, category := range decoded.Failed {
		for _, entries := range category {
			for _, entry := range entries {
				name, reason := refusedAccount(entry)
				if name == "" {
					// A failure the adapter cannot name is still a failure the
					// directory reported: it is carried as an uncertain outcome
					// rather than dropped, because dropping it read as a success.
					unnamed = append(unnamed, fmt.Sprintf("%v", entry))
					continue
				}
				refused[name] = reason
			}
		}
	}
	if len(unnamed) > 0 {
		sort.Strings(unnamed)
		return &UncertainChange{Method: method, Group: group, Users: users,
			Err: fmt.Errorf("the directory refused a part of the batch in a shape that names no account: %s",
				strings.Join(unnamed, "; "))}
	}
	if len(refused) > 0 {
		applied := make([]string, 0, len(users))
		for _, user := range users {
			if _, no := refused[user]; !no {
				applied = append(applied, user)
			}
		}
		return &PartialChange{Method: method, Group: group, Applied: applied, Refused: refused}
	}
	return nil
}

// refusedAccount reads one entry of the directory's failure list. The entry is
// a pair of the account and the reason - ["alice", "This entry is already a
// member"] - and anything else is reported without a name, because a name
// guessed out of an unknown shape would end the wrong session.
func refusedAccount(entry any) (string, string) {
	pair, ok := entry.([]any)
	if !ok || len(pair) == 0 {
		return "", ""
	}
	name, ok := pair[0].(string)
	if !ok {
		return "", ""
	}
	reason := "the directory gave no reason"
	if len(pair) > 1 {
		if text, ok := pair[1].(string); ok && text != "" {
			reason = text
		}
	}
	return name, reason
}

// SetUserSSHKeys sets the complete set of an account's public keys. A private
// key never reaches the system.
func (c *Client) SetUserSSHKeys(ctx context.Context, uid string, keys []string) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	for _, key := range keys {
		if err := validateSSHPublicKey(key); err != nil {
			return err
		}
	}
	value := any(keys)
	if len(keys) == 0 {
		// An empty list removes every key; the directory then expects null.
		value = nil
	}
	if _, err := c.call(ctx, "user_mod", []string{uid},
		map[string]any{"ipasshpubkey": value}); err != nil {
		return fmt.Errorf("changing the SSH keys of the account %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// ShowUser reads a single account.
func (c *Client) ShowUser(ctx context.Context, uid string) (*User, error) {
	if !userNamePattern.MatchString(uid) {
		return nil, fmt.Errorf("invalid account name %q", uid)
	}
	result, err := c.call(ctx, "user_show", []string{uid}, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, err
	}
	user := userFromRecord(decoded.Result, false)
	return &user, nil
}

// invalidate clears the cache after a change in the directory, so that the
// next read does not show the state from before the change.
func (c *Client) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = map[string]cacheEntry{}
	c.generation++
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// EnsureHostWithOTP makes sure the host entry exists in the directory and
// returns the single-use join password.
func (c *Client) EnsureHostWithOTP(ctx context.Context, fqdn string) (string, error) {
	if !hostNamePattern.MatchString(fqdn) {
		return "", fmt.Errorf("invalid host name %q", fqdn)
	}

	// The host may already exist in the directory; we then refresh the
	// password alone instead of creating the entry anew.
	result, err := c.call(ctx, "host_add", []string{fqdn}, map[string]any{
		"random": true,
		"force":  true,
	})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return "", fmt.Errorf("the host entry %s: %w", fqdn, err)
		}
		result, err = c.call(ctx, "host_mod", []string{fqdn}, map[string]any{"random": true})
		if err != nil && strings.Contains(err.Error(), "enrolled host") {
			// The entry still carries a keytab - a previous life of this host that was
			// reinstalled without leaving, or a join that broke after the directory's
			// half.
			if _, err := c.call(ctx, "host_disable", []string{fqdn}, map[string]any{}); err != nil {
				return "", fmt.Errorf("revoking the stale keytab of the host %s: %w", fqdn, err)
			}
			result, err = c.call(ctx, "host_mod", []string{fqdn}, map[string]any{"random": true})
		}
		if err != nil {
			return "", fmt.Errorf("refreshing the password of the host %s: %w", fqdn, err)
		}
	}

	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return "", err
	}
	password := first(decoded.Result, "randompassword")
	if password == "" {
		return "", fmt.Errorf("the directory returned no single-use password for %s", fqdn)
	}
	c.invalidate()
	return password, nil
}

// AddHostGroupMembers adds hosts to a host group.
func (c *Client) AddHostGroupMembers(ctx context.Context, group string, hosts []string) error {
	return c.changeHostGroupMembers(ctx, "hostgroup_add_member", group, hosts)
}

// RemoveHostGroupMembers removes hosts from a host group.
func (c *Client) RemoveHostGroupMembers(ctx context.Context, group string, hosts []string) error {
	return c.changeHostGroupMembers(ctx, "hostgroup_remove_member", group, hosts)
}

func (c *Client) changeHostGroupMembers(ctx context.Context, method, group string, hosts []string) error {
	if !groupNamePattern.MatchString(group) {
		return fmt.Errorf("invalid host group name %q", group)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts to change the membership of")
	}
	for _, host := range hosts {
		if !hostNamePattern.MatchString(host) {
			return fmt.Errorf("invalid host name %q", host)
		}
	}
	result, err := c.call(ctx, method, []string{group}, map[string]any{"host": hosts})
	if err != nil {
		return fmt.Errorf("changing the membership of the host group %s: %w", group, err)
	}
	// A partial success comes back as a list of failures, not as an error,
	// and must not pass as a success.
	if problems := failedMembers(result); len(problems) > 0 {
		return fmt.Errorf("some hosts were not changed: %s", strings.Join(problems, "; "))
	}
	c.invalidate()
	return nil
}

// Expiry names the two Kerberos expirations of an account.
type Expiry struct {
	PrincipalExpiresAt *time.Time
	PasswordExpiresAt  *time.Time
}

// Empty says the change names nothing.
func (e Expiry) Empty() bool {
	return e.PrincipalExpiresAt == nil && e.PasswordExpiresAt == nil
}

// SetUserExpiry sets or clears the expirations of an account.
func (c *Client) SetUserExpiry(ctx context.Context, uid string, expiry Expiry) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	if expiry.Empty() {
		return fmt.Errorf("the expiry change names no expiration")
	}
	options := map[string]any{}
	if expiry.PrincipalExpiresAt != nil {
		options["krbprincipalexpiration"] = expiryValue(*expiry.PrincipalExpiresAt)
	}
	if expiry.PasswordExpiresAt != nil {
		options["krbpasswordexpiration"] = expiryValue(*expiry.PasswordExpiresAt)
	}
	if _, err := c.call(ctx, "user_mod", []string{uid}, options); err != nil && !isEmptyModification(err) {
		return fmt.Errorf("changing the expiration of the account %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// expiryValue renders an expiration for the directory; the zero time
// becomes null, which the directory reads as "remove the attribute".
func expiryValue(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return GeneralizedTime(at)
}

// POSIXSpec names the POSIX attributes of an account to change. An empty
// field is left as it is.
type POSIXSpec struct {
	UIDNumber string
	GIDNumber string
	Shell     string
	HomeDir   string
}

// Validate checks the shape before anything goes to the directory.
func (s POSIXSpec) Validate() error {
	for name, value := range map[string]string{"uid number": s.UIDNumber, "gid number": s.GIDNumber} {
		if value == "" {
			continue
		}
		if !posixIDPattern.MatchString(value) {
			return fmt.Errorf("invalid %s %q", name, value)
		}
	}
	if s.Shell != "" && !absolutePathPattern.MatchString(s.Shell) {
		return fmt.Errorf("the shell must be an absolute path, not %q", s.Shell)
	}
	if s.HomeDir != "" && !absolutePathPattern.MatchString(s.HomeDir) {
		return fmt.Errorf("the home directory must be an absolute path, not %q", s.HomeDir)
	}
	if s.UIDNumber == "" && s.GIDNumber == "" && s.Shell == "" && s.HomeDir == "" {
		return fmt.Errorf("the POSIX change names no attribute")
	}
	return nil
}

// The shapes of POSIX attributes: a number for the identifiers, an absolute
// path for the shell and the home directory.
var (
	posixIDPattern      = regexp.MustCompile(`^[0-9]{1,10}$`)
	absolutePathPattern = regexp.MustCompile(`^/[^\s]*$`)
)

// SetUserPOSIX changes the POSIX attributes of an account.
func (c *Client) SetUserPOSIX(ctx context.Context, uid string, spec POSIXSpec) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	options := map[string]any{}
	if spec.UIDNumber != "" {
		options["uidnumber"] = spec.UIDNumber
	}
	if spec.GIDNumber != "" {
		options["gidnumber"] = spec.GIDNumber
	}
	if spec.Shell != "" {
		options["loginshell"] = spec.Shell
	}
	if spec.HomeDir != "" {
		options["homedirectory"] = spec.HomeDir
	}
	if _, err := c.call(ctx, "user_mod", []string{uid}, options); err != nil && !isEmptyModification(err) {
		return fmt.Errorf("changing the POSIX attributes of the account %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// PreserveUser removes an account while keeping its entry: the directory moves
// it among the preserved accounts, where the UID and the history stay and
// nothing can sign in as it.
func (c *Client) PreserveUser(ctx context.Context, uid string) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	if _, err := c.call(ctx, "user_del", []string{uid}, map[string]any{"preserve": true}); err != nil {
		return fmt.Errorf("preserving the account %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// ErrEntryMoved says the directory no longer holds the entry the way the plan
// described it: another name, another entry under the same name, or a change
// somebody made in between.
var ErrEntryMoved = errors.New("the entry is not the one the plan named")

// PreserveProof says what was established about the entry after the move.
// Confirmed means the preserved entry was read back and carries the identifier
// the plan named; anything else is a preserve that was carried out and not
// proven, and Detail says which of the reasons it is. A preserve nobody could
// confirm is not a preserve nobody carried out, and it is not a confirmed one
// either - so it travels as neither.
type PreserveProof struct {
	Confirmed bool
	Detail    string
}

// PreserveUserAt preserves an account only while it is still the entry the
// plan was made for, and says what it could prove about the entry afterwards.
func (c *Client) PreserveUserAt(ctx context.Context, uid string, planned EntryReference) (PreserveProof, error) {
	if !userNamePattern.MatchString(uid) {
		return PreserveProof{}, fmt.Errorf("invalid account name %q", uid)
	}
	if !planned.Complete() {
		return PreserveProof{}, fmt.Errorf("%w: the plan names no entry to bind to", ErrEntryMoved)
	}
	current, err := c.UserEntry(ctx, uid)
	if err != nil {
		return PreserveProof{}, err
	}
	if reason, moved := planned.Moved(current); moved {
		return PreserveProof{}, fmt.Errorf("%w: %s (the plan was %s)", ErrEntryMoved, reason, planned.Binding())
	}
	if err := c.PreserveUser(ctx, uid); err != nil {
		return PreserveProof{}, err
	}

	// The directory offers no compare-and-delete, so the binding is proven
	// after the fact - and what makes that honest is that a preserve is
	// undoable. Between the check above and the call, the entry could be
	// deleted and another created under the same name, and the operator's
	// consent for the first would have been carried out on the second.
	after, err := c.PreservedEntry(ctx, uid)
	if errors.Is(err, ErrPreservedReadUnsupported) {
		// Could not ask is not disproven. The preserve was carried out and the
		// binding before the call held; this directory simply offers no read of
		// its preserved accounts, so there is no after-the-fact proof to have.
		// Treating that as a failure undid every successful preserve on such a
		// directory - which is the same mistake as reading "the probe could not
		// run" as "the answer is no". It is reported as unproven, because
		// reporting it as proven was the other half of the same mistake.
		return PreserveProof{Detail: "this directory offers no read of its preserved accounts, so the " +
			"entry was not read after the move; the binding before it is the whole of the proof (" +
			planned.Binding() + ")"}, nil
	}
	if err != nil {
		return PreserveProof{Detail: "the preserved entry could not be read back, so it is not known " +
			"whether it is the entry the plan named: " + err.Error()}, nil
	}
	// Judged by the identifier alone: the preserve itself moved the entry and
	// stamped it, so the DN and the timestamp have changed by definition and
	// comparing them would refuse every preserve that worked.
	if reason, moved := planned.Replaced(after); moved {
		if undo := c.UndeleteUser(ctx, uid); undo != nil {
			return PreserveProof{}, fmt.Errorf("%w: %s; putting it back failed too, so %s stays preserved and "+
				"needs a person: %v", ErrEntryMoved, reason, uid, undo)
		}
		return PreserveProof{}, fmt.Errorf("%w: %s; the account was put back", ErrEntryMoved, reason)
	}
	// Replaced answers "no" where there is nothing to compare, which is the
	// answer a caller needs for the decision to put the account back and not
	// the answer it needs for the trail: without an identifier on either side
	// the entry after the move was never identified.
	if missing := unidentified(planned, after); missing != "" {
		return PreserveProof{Detail: missing + ", so there was nothing to compare after the move; " +
			"the binding before it is the whole of the proof (" + planned.Binding() + ")"}, nil
	}
	return PreserveProof{Confirmed: true,
		Detail: "the preserved entry carries the identifier the plan named (" + after.EntryUUID + ")"}, nil
}

// unidentified names the side that carries no identifier, and an empty string
// when both do.
func unidentified(planned, after EntryReference) string {
	switch {
	case planned.EntryUUID == "" && after.EntryUUID == "":
		return "neither the plan nor the preserved entry carries an identifier"
	case planned.EntryUUID == "":
		return "the plan carries no identifier of the entry"
	case after.EntryUUID == "":
		return "the directory reports no identifier for the preserved entry"
	}
	return ""
}

// PreservedEntry reads a preserved account, which user_show does not return
// without being told to look among them.
// ErrPreservedReadUnsupported means this directory offers no read of the
// preserved accounts. The option exists in the API of FreeIPA and not in every
// build of it: on 04.10 user_show answered "Unknown option: preserved
// (OptionError)". It is a limit of the directory, not a fact about the entry.
var ErrPreservedReadUnsupported = errors.New("the directory offers no read of the preserved accounts")

func (c *Client) PreservedEntry(ctx context.Context, uid string) (EntryReference, error) {
	if !userNamePattern.MatchString(uid) {
		return EntryReference{}, fmt.Errorf("invalid account name %q", uid)
	}
	// user_find and not user_show: the preserved flag belongs to the search in
	// every build that has it at all, and user_show refused the option on the
	// directory of 04.10 - which turned every successful preserve into a
	// failure, because the read back could not be made.
	result, err := c.call(ctx, "user_find", []string{uid},
		map[string]any{"all": true, "preserved": true, "sizelimit": 2})
	if err != nil {
		var refusal *DirectoryError
		switch {
		case errors.As(err, &refusal) && refusal.Name == "NotFound":
			return EntryReference{}, fmt.Errorf("%w: %s", ErrEntryNotFound, uid)
		case errors.As(err, &refusal) && refusal.Name == "OptionError":
			return EntryReference{}, fmt.Errorf("%w: %s", ErrPreservedReadUnsupported, refusal.Message)
		}
		return EntryReference{}, err
	}
	var decoded struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return EntryReference{}, err
	}
	// A search answers with a list. The name is the one asked for, so more than
	// one entry is a directory holding two accounts under one name - which is
	// not something to pick from.
	switch len(decoded.Result) {
	case 0:
		return EntryReference{}, fmt.Errorf("%w: %s", ErrEntryNotFound, uid)
	case 1:
		return entryFromRecord(decoded.Result[0]), nil
	}
	return EntryReference{}, fmt.Errorf("the directory holds %d preserved accounts named %s",
		len(decoded.Result), uid)
}

// UndeleteUser brings a preserved account back, which is what makes the check
// after a preserve something other than an observation.
func (c *Client) UndeleteUser(ctx context.Context, uid string) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	if _, err := c.call(ctx, "user_undel", []string{uid}, nil); err != nil {
		return fmt.Errorf("putting the account %s back: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// ResetUserPassword asks the directory for a new password of the account.
func (c *Client) ResetUserPassword(ctx context.Context, uid string) (string, error) {
	if !userNamePattern.MatchString(uid) {
		return "", fmt.Errorf("invalid account name %q", uid)
	}
	result, err := c.call(ctx, "user_mod", []string{uid}, map[string]any{"random": true})
	if err != nil {
		return "", fmt.Errorf("resetting the password of the account %s: %w", uid, err)
	}
	var decoded struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return "", err
	}
	password := first(decoded.Result, "randompassword")
	if password == "" {
		return "", fmt.Errorf("the directory returned no password for %s", uid)
	}
	c.invalidate()
	return password, nil
}
