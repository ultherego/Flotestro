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

// Domyslny zakres UID kont ludzi. Wartosci pochodza z /etc/login.defs, gdy
// plik jest czytelny; te sa awaryjne i zgodne z ustawieniami dystrybucji.
const (
	defaultUIDMin = 1000
	defaultUIDMax = 60000
)

// AccountSource opisuje pochodzenie konta.
type AccountSource string

const (
	SourceLocal     AccountSource = "local"
	SourceDirectory AccountSource = "directory"
	SourceSystem    AccountSource = "system"
)

// SSHKeyInfo opisuje klucz publiczny odciskiem. Sama tresc klucza nie jest
// przesylana: do identyfikacji wystarcza odcisk.
type SSHKeyInfo struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Source      string `json:"source,omitempty"`
}

// LocalAccount opisuje konto widoczne na hoscie.
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
	// PasswordSet rozroznia konto bez hasla od konta z haslem. Nil oznacza
	// stan nieustalony i nie moze byc pokazany jako "brak hasla".
	PasswordSet *bool        `json:"password_set,omitempty"`
	SSHKeys     []SSHKeyInfo `json:"ssh_keys,omitempty"`

	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ReadLocalAccounts czyta konta z /etc/passwd. Plik jest czytelny dla
// wszystkich, wiec ta czesc nie wymaga helpera.
//
// Konta z katalogu nie sa tu widoczne: NSS rozwiazuje je dopiero na zadanie,
// a pobieranie pelnej listy uzytkownikow domeny z kazdego hosta byloby
// dokladnie tym obciazeniem katalogu, przed ktorym broni sie dokument.
func ReadLocalAccounts() []LocalAccount {
	uidMin, uidMax := parseUIDRange("/etc/login.defs")
	return parsePasswd("/etc/passwd", uidMin, uidMax, groupsOf)
}

// parsePasswd czyta konta z podanego pliku. Sciezka i zrodlo grup sa
// parametrami, zeby klasyfikacja dala sie sprawdzic bez zmieniania systemu.
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
		// Konto spoza zakresu kont ludzi nalezy do uslugi. Sam prog dolny nie
		// wystarcza: "nobody" ma UID 65534 i lezy powyzej zakresu, a nie jest
		// kontem czlowieka.
		if uid < uint64(uidMin) || uid > uint64(uidMax) {
			account.Source = SourceSystem
		}
		account.Groups = groups(fields[0])
		accounts = append(accounts, account)
	}
	return accounts
}

// loginDefsUIDRange odczytuje zakres UID kont ludzi z konfiguracji systemu.
// Dystrybucje roznia sie tu miedzy soba, a useradd trzyma sie tego pliku,
// wiec klasyfikacja panelu musi wynikac z tego samego zrodla.
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

// groupsOf zwraca grupy konta. Blad odczytu daje pusta liste, a nie brak
// wpisu: konto istnieje niezaleznie od tego, czy znamy jego grupy.
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

// mergePrivilegedAccounts uzupelnia konta o dane wymagajace roota: stan
// blokady i klucze SSH.
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

// ProbeLocalAccounts uzupelnia konta przez helpera o stan blokady i klucze.
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
