package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	record := decoded.Result
	return &User{
		UID:                first(record, "uid"),
		FirstName:          first(record, "givenname"),
		LastName:           first(record, "sn"),
		DisplayName:        first(record, "displayname"),
		Email:              strings_(record, "mail"),
		UIDNumber:          first(record, "uidnumber"),
		GIDNumber:          first(record, "gidnumber"),
		HomeDir:            first(record, "homedirectory"),
		Shell:              first(record, "loginshell"),
		Groups:             strings_(record, "memberof_group"),
		Disabled:           boolean(record, "nsaccountlock"),
		SSHKeyFingerprints: strings_(record, "sshpubkeyfp"),
	}, nil
}

// invalidate clears the cache after a change in the directory, so that the
// next read does not show the state from before the change.
func (c *Client) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = map[string]cacheEntry{}
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
