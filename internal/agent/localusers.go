package agent

import (
	"context"
	"errors"
	"os/user"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/accounts"
)

// AccountSource describes where an account comes from.
type AccountSource string

const (
	SourceLocal     AccountSource = "local"
	SourceDirectory AccountSource = "directory"
	SourceSystem    AccountSource = "system"
)

// SSHKeyInfo describes a public key by its fingerprint. The content of the key
// itself is not transmitted: the fingerprint is enough to identify it.
type SSHKeyInfo struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Source      string `json:"source,omitempty"`
}

// LocalAccount describes an account visible on the host.
type LocalAccount struct {
	Name   string        `json:"name"`
	UID    uint32        `json:"uid"`
	GID    uint32        `json:"gid"`
	Home   string        `json:"home,omitempty"`
	Shell  string        `json:"shell,omitempty"`
	Gecos  string        `json:"gecos,omitempty"`
	Source AccountSource `json:"source"`
	Groups []string      `json:"groups,omitempty"`
	Locked *bool         `json:"locked,omitempty"`
	// PasswordSet tells an account without a password from one with a password.
	PasswordSet *bool        `json:"password_set,omitempty"`
	SSHKeys     []SSHKeyInfo `json:"ssh_keys,omitempty"`
	// ExpiresAt is the expiry date as YYYY-MM-DD from the shadow record.
	ExpiresAt string `json:"expires_at,omitempty"`

	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ReadLocalAccounts reads the accounts from /etc/passwd. The file is readable
// by everyone, so this part needs no helper.
func ReadLocalAccounts() []LocalAccount {
	return parsePasswd("/etc/passwd", accounts.LoadUIDRange(), groupsOf)
}

// parsePasswd reads the accounts from the given file.
func parsePasswd(path string, uidRange accounts.UIDRange, groups func(string) []string) []LocalAccount {
	var found []LocalAccount
	for line := range iterLines(path) {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		gid, _ := strconv.ParseUint(fields[3], 10, 32)

		account := LocalAccount{
			Name:   fields[0],
			UID:    uint32(uid),
			GID:    uint32(gid),
			Gecos:  strings.TrimRight(fields[4], ","),
			Home:   fields[5],
			Shell:  fields[6],
			Source: SourceLocal,
		}
		// An account outside the range of the accounts of people belongs to a
		// service.
		if uidRange.IsSystem(int64(uid)) {
			account.Source = SourceSystem
		}
		account.Groups = groups(fields[0])
		found = append(found, account)
	}
	return found
}

// groupsOf returns the groups of an account.
func groupsOf(name string) []string {
	account, err := user.Lookup(name)
	if err != nil {
		return nil
	}
	ids, err := account.GroupIds()
	if err != nil {
		return nil
	}
	var groups []string
	for _, id := range ids {
		if group, err := user.LookupGroupId(id); err == nil {
			groups = append(groups, group.Name)
		}
	}
	return groups
}

// mergePrivilegedAccounts fills the accounts in with the data that needs root:
// the lock state and the SSH keys.
func mergePrivilegedAccounts(accounts []LocalAccount, result *helperv1.LocalAccountsResult) []LocalAccount {
	if result == nil {
		return accounts
	}
	byName := map[string]*helperv1.LocalAccountDetail{}
	for _, detail := range result.GetAccounts() {
		byName[detail.GetName()] = detail
	}

	for index := range accounts {
		detail, found := byName[accounts[index].Name]
		if !found {
			continue
		}
		accounts[index].Locked = detail.Locked
		accounts[index].PasswordSet = detail.PasswordSet
		accounts[index].ExpiresAt = detail.GetExpiresAt()
		for _, key := range detail.GetSshKeys() {
			// A helper from before the managed file names no source; its
			// keys came from the user's file, the only one it read.
			source := key.GetSource()
			if source == "" {
				source = "authorized_keys"
			}
			accounts[index].SSHKeys = append(accounts[index].SSHKeys, SSHKeyInfo{
				Fingerprint: key.GetFingerprint(),
				Type:        key.GetType(),
				Comment:     key.GetComment(),
				Source:      source,
			})
		}
		if reason := result.GetUnavailableReason(); reason != "" {
			accounts[index].UnavailableReason = reason
		}
	}
	return accounts
}

func localAccountsToProto(accounts []LocalAccount) []*agentv1.LocalAccount {
	result := make([]*agentv1.LocalAccount, 0, len(accounts))
	for _, account := range accounts {
		keys := make([]*agentv1.SSHKey, 0, len(account.SSHKeys))
		for _, key := range account.SSHKeys {
			keys = append(keys, &agentv1.SSHKey{
				Fingerprint: key.Fingerprint, Type: key.Type,
				Comment: key.Comment, Source: key.Source,
			})
		}
		result = append(result, &agentv1.LocalAccount{
			Name:              account.Name,
			Uid:               account.UID,
			Gid:               account.GID,
			Home:              account.Home,
			Shell:             account.Shell,
			Gecos:             account.Gecos,
			Source:            sourceToProto(account.Source),
			Groups:            account.Groups,
			Locked:            account.Locked,
			PasswordSet:       account.PasswordSet,
			SshKeys:           keys,
			ExpiresAt:         account.ExpiresAt,
			UnavailableReason: account.UnavailableReason,
		})
	}
	return result
}

func sourceToProto(source AccountSource) agentv1.LocalAccount_Source {
	switch source {
	case SourceLocal:
		return agentv1.LocalAccount_SOURCE_LOCAL
	case SourceDirectory:
		return agentv1.LocalAccount_SOURCE_DIRECTORY
	case SourceSystem:
		return agentv1.LocalAccount_SOURCE_SYSTEM
	default:
		return agentv1.LocalAccount_SOURCE_UNSPECIFIED
	}
}

// ProbeLocalAccounts fills the accounts in through the helper with the lock
// state and the keys.
func (e *TaskExecutor) ProbeLocalAccounts(ctx context.Context, names []string) (*helperv1.LocalAccountsResult, error) {
	response, err := e.helper.Call(ctx, &helperv1.HelperRequest{
		TaskId:         "local-accounts",
		TimeoutSeconds: 60,
		Action: &helperv1.HelperRequest_LocalAccounts{
			LocalAccounts: &helperv1.LocalAccountsRequest{Names: names},
		},
	}, 60*time.Second)
	if err != nil {
		return nil, err
	}
	if !response.GetAccepted() {
		return nil, errors.New(response.GetErrorCode() + ": " + response.GetMessage())
	}
	return response.GetAccountsResult(), nil
}
