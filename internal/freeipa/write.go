package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Operacje zapisu sa wykonywane wylacznie przez jawnie wspierane polecenia
// katalogu. Kazda ma odpowiednik w liscie allowedMethods; dopisanie nowej
// operacji wymaga swiadomej zmiany tej listy.

// UserSpec opisuje konto do utworzenia.
type UserSpec struct {
	UID       string
	FirstName string
	LastName  string
	Email     string
	Shell     string
	// Groups to grupy, do ktorych konto ma nalezec po utworzeniu.
	Groups []string
	// SSHKeys sa kluczami publicznymi. Klucz prywatny nigdy nie trafia
	// do systemu.
	SSHKeys []string
}

// Validate sprawdza spojnosc opisu konta.
func (s UserSpec) Validate() error {
	if !userNamePattern.MatchString(s.UID) {
		return fmt.Errorf("nieprawidlowa nazwa konta %q", s.UID)
	}
	if strings.TrimSpace(s.LastName) == "" {
		return fmt.Errorf("konto wymaga nazwiska")
	}
	for _, group := range s.Groups {
		if !groupNamePattern.MatchString(group) {
			return fmt.Errorf("nieprawidlowa nazwa grupy %q", group)
		}
	}
	for _, key := range s.SSHKeys {
		if err := validateSSHPublicKey(key); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser tworzy konto w katalogu i zwraca jego stan po utworzeniu.
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
		return nil, fmt.Errorf("utworzenie konta %s: %w", spec.UID, err)
	}
	c.invalidate()
	return c.ShowUser(ctx, spec.UID)
}

// SetUserEnabled wlacza albo blokuje konto. Blokada w katalogu jest jedynie
// jednym z krokow odbierania dostepu: sesje panelu trzeba uniewaznic osobno.
func (c *Client) SetUserEnabled(ctx context.Context, uid string, enabled bool) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("nieprawidlowa nazwa konta %q", uid)
	}
	method := "user_disable"
	if enabled {
		method = "user_enable"
	}
	if _, err := c.call(ctx, method, []string{uid}, nil); err != nil {
		// Katalog zglasza blad takze wtedy, gdy konto juz jest w zadanym
		// stanie; to nie jest niepowodzenie operacji.
		if strings.Contains(err.Error(), "already") {
			c.invalidate()
			return nil
		}
		return fmt.Errorf("zmiana stanu konta %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// AddGroupMembers dodaje konta do grupy.
func (c *Client) AddGroupMembers(ctx context.Context, group string, users []string) error {
	return c.changeGroupMembers(ctx, "group_add_member", group, users)
}

// RemoveGroupMembers usuwa konta z grupy.
func (c *Client) RemoveGroupMembers(ctx context.Context, group string, users []string) error {
	return c.changeGroupMembers(ctx, "group_remove_member", group, users)
}

func (c *Client) changeGroupMembers(ctx context.Context, method, group string, users []string) error {
	if !groupNamePattern.MatchString(group) {
		return fmt.Errorf("nieprawidlowa nazwa grupy %q", group)
	}
	if len(users) == 0 {
		return fmt.Errorf("brak kont do zmiany czlonkostwa")
	}
	for _, user := range users {
		if !userNamePattern.MatchString(user) {
			return fmt.Errorf("nieprawidlowa nazwa konta %q", user)
		}
	}

	result, err := c.call(ctx, method, []string{group}, map[string]any{"user": users})
	if err != nil {
		return fmt.Errorf("zmiana czlonkostwa w grupie %s: %w", group, err)
	}

	// Katalog zwraca liste niepowodzen zamiast bledu, gdy czesc kont nie
	// zostala dodana. Czesciowy sukces nie moze uchodzic za sukces.
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
			return fmt.Errorf("czesc kont nie zostala zmieniona: %s", strings.Join(problems, "; "))
		}
	}
	c.invalidate()
	return nil
}

// SetUserSSHKeys ustawia komplet kluczy publicznych konta. Klucz prywatny
// nigdy nie trafia do systemu.
func (c *Client) SetUserSSHKeys(ctx context.Context, uid string, keys []string) error {
	if !userNamePattern.MatchString(uid) {
		return fmt.Errorf("nieprawidlowa nazwa konta %q", uid)
	}
	for _, key := range keys {
		if err := validateSSHPublicKey(key); err != nil {
			return err
		}
	}
	value := any(keys)
	if len(keys) == 0 {
		// Pusta lista usuwa wszystkie klucze; katalog oczekuje wtedy null.
		value = nil
	}
	if _, err := c.call(ctx, "user_mod", []string{uid},
		map[string]any{"ipasshpubkey": value}); err != nil {
		return fmt.Errorf("zmiana kluczy SSH konta %s: %w", uid, err)
	}
	c.invalidate()
	return nil
}

// ShowUser odczytuje pojedyncze konto.
func (c *Client) ShowUser(ctx context.Context, uid string) (*User, error) {
	if !userNamePattern.MatchString(uid) {
		return nil, fmt.Errorf("nieprawidlowa nazwa konta %q", uid)
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

// invalidate czysci cache po zmianie w katalogu, zeby kolejny odczyt nie
// pokazal stanu sprzed zmiany.
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

// EnsureHostWithOTP zapewnia wpis hosta w katalogu i zwraca jednorazowe
// haslo dolaczenia.
//
// Haslo jest generowane przez katalog, wazne do pierwszego uzycia i wylacznie
// dla tego jednego hosta. Wspolne haslo administratora rozeslane do calej
// floty byloby dokladnie tym, przed czym broni sie dokument.
func (c *Client) EnsureHostWithOTP(ctx context.Context, fqdn string) (string, error) {
	if !hostNamePattern.MatchString(fqdn) {
		return "", fmt.Errorf("nieprawidlowa nazwa hosta %q", fqdn)
	}

	// Host moze juz istniec w katalogu; wtedy odswiezamy samo haslo zamiast
	// tworzyc wpis od nowa.
	result, err := c.call(ctx, "host_add", []string{fqdn}, map[string]any{
		"random": true,
		"force":  true,
	})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return "", fmt.Errorf("wpis hosta %s: %w", fqdn, err)
		}
		result, err = c.call(ctx, "host_mod", []string{fqdn}, map[string]any{"random": true})
		if err != nil {
			return "", fmt.Errorf("odswiezenie hasla hosta %s: %w", fqdn, err)
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
		return "", fmt.Errorf("katalog nie zwrocil hasla jednorazowego dla %s", fqdn)
	}
	c.invalidate()
	return password, nil
}
