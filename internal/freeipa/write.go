package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Write operations are carried out only through explicitly supported
// directory commands. Each one has its counterpart in the allowedMethods
// list; adding a new operation requires a deliberate change to that list.

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

// SetUserEnabled enables or locks an account. Locking in the directory is
// only one of the steps of taking access away: the panel sessions have to be
// revoked separately.
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
		return fmt.Errorf("changing the membership of the group %s: %w", group, err)
	}

	// The directory returns a list of failures instead of an error when some
	// of the accounts were not added. A partial success must not pass as a
	// success.
	var decoded struct {
		Failed map[string]map[string][]any `json:"failed"`
	}
	if err := json.Unmarshal(result, &decoded); err == nil {
		var problems []string
		for _, category := range decoded.Failed {
			for _, entries := range category {
				for _, entry := range entries {
					problems = append(problems, fmt.Sprint(entry))
				}
			}
		}
		if len(problems) > 0 {
			return fmt.Errorf("some accounts were not changed: %s", strings.Join(problems, "; "))
		}
	}
	c.invalidate()
	return nil
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
//
// The password is generated by the directory, valid until its first use and
// for that one host alone. A shared administrator password handed out to the
// whole fleet would be exactly what the document guards against.
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
			// The entry still carries a keytab - a previous life of this host
			// that was reinstalled without leaving, or a join that broke
			// after the directory's half. The operator ordered a join of
			// this host, so the stale keytab is revoked and the password is
			// issued anew; the entry and its history stay.
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

// AddHostGroupMembers adds hosts to a host group. The rules reach a host
// through its groups, so this is a change of access and goes through the
// same plan and approval as a user group change.
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

// Expiry names the two Kerberos expirations of an account. A nil field is
// left as it is; a pointer to the zero time clears the expiration, so that
// "never expires" can be ordered as deliberately as a date.
type Expiry struct {
	PrincipalExpiresAt *time.Time
	PasswordExpiresAt  *time.Time
}

// Empty says the change names nothing.
func (e Expiry) Empty() bool {
	return e.PrincipalExpiresAt == nil && e.PasswordExpiresAt == nil
}

// SetUserExpiry sets or clears the expirations of an account. The
// principal expiration ends every Kerberos authentication of the account
// at that moment; the password expiration makes the next login change the
// password. Neither locks the account: a lock is a separate change with
// its own plan.
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

// The shapes of POSIX attributes: a number for the identifiers, an
// absolute path for the shell and the home directory. The directory
// validates too; this stops nonsense before the plan is even computed.
var (
	posixIDPattern      = regexp.MustCompile(`^[0-9]{1,10}$`)
	absolutePathPattern = regexp.MustCompile(`^/[^\s]*$`)
)

// SetUserPOSIX changes the POSIX attributes of an account. A new UID or GID
// number changes whom the files on every host belong to; the plan says so
// before anybody approves it.
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

// PreserveUser removes an account while keeping its entry: the directory
// moves it among the preserved accounts, where the UID and the history
// stay and nothing can sign in as it. This is the only removal the adapter
// carries out - a user_del without preserve is refused by the client
// before any request is built.
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

// ErrEntryMoved says the directory no longer holds the entry the way the
// plan described it: another name, another entry under the same name, or a
// change somebody made in between. It is a refusal rather than a failure -
// nothing was ordered - and the caller reports it as a stale plan.
var ErrEntryMoved = errors.New("the entry is not the one the plan named")

// PreserveUserAt preserves an account only while it is still the entry the
// plan was made for.
//
// The check lives here rather than only in the caller because the adapter
// is the last place before the directory: a preserve carries the entry's
// distinguished name, its unique identifier and its modify timestamp where
// the directory reports one, and every one of those the plan has is read
// again and compared before the move is ordered. What the directory does
// not report is not invented - a plan bound to two of the three says so -
// and what it does report has to agree.
//
// The window between the read and the move is not closed by this: it is
// made small and observable. A directory that moved the entry in that
// instant refuses the move itself, which is why the directory goes first
// and nothing local is touched until it has answered.
func (c *Client) PreserveUserAt(ctx context.Context, uid string, planned EntryReference) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("invalid account name %q", uid)
	}
	if !planned.Complete() {
		return fmt.Errorf("%w: the plan names no entry to bind to", ErrEntryMoved)
	}
	current, err := c.UserEntry(ctx, uid)
	if err != nil {
		return err
	}
	if reason, moved := planned.Moved(current); moved {
		return fmt.Errorf("%w: %s (the plan was %s)", ErrEntryMoved, reason, planned.Binding())
	}
	return c.PreserveUser(ctx, uid)
}

// ResetUserPassword asks the directory for a new password of the account.
// The directory generates it and marks it expired, so the first login has
// to change it. The value is returned to the caller once and is neither
// kept nor logged here; a caller that stores it breaks the document's rule
// that a secret is never in a job output.
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
