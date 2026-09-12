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
)

// The default UID range of the accounts of people. The values come from
// /etc/login.defs when the file is readable; these are the fallback and match
// the settings of the distributions.
const (
	defaultUIDMin = 1000
	defaultUIDMax = 60000
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
	// Nil means a state that was not determined and must not be shown as "no
	// password".
	PasswordSet *bool        `json:"password_set,omitempty"`
	SSHKeys     []SSHKeyInfo `json:"ssh_keys,omitempty"`

	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ReadLocalAccounts reads the accounts from /etc/passwd. The file is readable
// by everyone, so this part needs no helper.
//
// The accounts from the directory are not visible here: NSS resolves them only
// on request, and fetching the full list of domain users from every host would
// be exactly the load on the directory the document guards against.
func ReadLocalAccounts() []LocalAccount {
	uidMin, uidMax := parseUIDRange("/etc/login.defs")
	return parsePasswd("/etc/passwd", uidMin, uidMax, groupsOf)
}

// parsePasswd reads the accounts from the given file. The path and the source
// of the groups are parameters so that the classification can be checked
// without changing the system.
func parsePasswd(path string, uidMin, uidMax int64, groups func(string) []string) []LocalAccount {
	var accounts []LocalAccount
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
		// service. The lower bound alone is not enough: "nobody" has UID 65534,
		// which lies above the range, and is not the account of a person.
		if uid < uint64(uidMin) || uid > uint64(uidMax) {
			account.Source = SourceSystem
		}
		account.Groups = groups(fields[0])
		accounts = append(accounts, account)
	}
	return accounts
}

// parseUIDRange reads the UID range of the accounts of people from the system
// configuration. Distributions differ here, and useradd follows this file, so
// the classification of the panel has to follow the same source.
func parseUIDRange(path string) (int64, int64) {
	uidMin, uidMax := int64(defaultUIDMin), int64(defaultUIDMax)
	for line := range iterLines(path) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			uidMin = value
		case "UID_MAX":
			uidMax = value
		}
	}
	if uidMax < uidMin {
		return defaultUIDMin, defaultUIDMax
	}
	return uidMin, uidMax
}

// groupsOf returns the groups of an account. A read error gives an empty list
// and not a missing entry: the account exists regardless of whether its groups
// are known.
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
		for _, key := range detail.GetSshKeys() {
			accounts[index].SSHKeys = append(accounts[index].SSHKeys, SSHKeyInfo{
				Fingerprint: key.GetFingerprint(),
				Type:        key.GetType(),
				Comment:     key.GetComment(),
				Source:      "authorized_keys",
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
