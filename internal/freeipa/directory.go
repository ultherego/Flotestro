package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// User jest kontem POSIX w katalogu. Panel nie przechowuje hasel ani kopii
// katalogu; te dane sa odczytywane na zadanie i krotko cache'owane.
type User struct {
	UID         string   `json:"uid"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       []string `json:"email,omitempty"`
	UIDNumber   string   `json:"uid_number,omitempty"`
	GIDNumber   string   `json:"gid_number,omitempty"`
	HomeDir     string   `json:"home_directory,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	// Disabled odpowiada nsaccountlock w katalogu.
	Disabled bool `json:"disabled"`
	// SSHKeyFingerprints pokazuje klucze bez ich tresci.
	SSHKeyFingerprints []string `json:"ssh_key_fingerprints,omitempty"`
}

// Group jest grupa POSIX.
type Group struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	GIDNumber   string   `json:"gid_number,omitempty"`
	Members     []string `json:"members,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
}

// Host jest wpisem hosta w katalogu.
type Host struct {
	FQDN        string   `json:"fqdn"`
	Description string   `json:"description,omitempty"`
	Enrolled    bool     `json:"enrolled"`
	EnrolledAt  string   `json:"enrolled_at,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
}

// HBACRule opisuje regule dostepu do hostow i uslug.
type HBACRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Users       []string `json:"users,omitempty"`
	UserGroups  []string `json:"user_groups,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	HostGroups  []string `json:"host_groups,omitempty"`
	Services    []string `json:"services,omitempty"`
	// AllowsEverything oznacza regule typu allow_all. Dokument zaleca jej
	// unikanie: otwiera dostep do calej floty jednym wpisem.
	AllowsEverything bool `json:"allows_everything"`
}

// SudoRule opisuje regule podniesienia uprawnien.
type SudoRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Users       []string `json:"users,omitempty"`
	UserGroups  []string `json:"user_groups,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	HostGroups  []string `json:"host_groups,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	RunAs       []string `json:"run_as,omitempty"`
	Options     []string `json:"options,omitempty"`
	// Critical oznacza regule o podwyzszonym ryzyku: NOPASSWD albo ALL.
	Critical bool `json:"critical"`
	// CriticalReasons opisuje, co konkretnie czyni regule ryzykowna.
	CriticalReasons []string `json:"critical_reasons,omitempty"`
}

// Ping sprawdza lacznosc i uwierzytelnienie connectora.
func (c *Client) Ping(ctx context.Context) (string, error) {
	result, err := c.call(ctx, "ping", nil, nil)
	if err != nil {
		return "", err
	}
	var decoded struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return "", err
	}
	return decoded.Summary, nil
}

// Users zwraca konta z katalogu.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	return cached(ctx, c, "users", func() ([]User, error) {
		records, err := c.findRecords(ctx, "user_find")
		if err != nil {
			return nil, err
		}
		users := make([]User, 0, len(records))
		for _, record := range records {
			users = append(users, User{
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
			})
		}
		return users, nil
	})
}

// Groups zwraca grupy z katalogu.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	return cached(ctx, c, "groups", func() ([]Group, error) {
		records, err := c.findRecords(ctx, "group_find")
		if err != nil {
			return nil, err
		}
		groups := make([]Group, 0, len(records))
		for _, record := range records {
			groups = append(groups, Group{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				GIDNumber:   first(record, "gidnumber"),
				Members:     strings_(record, "member_user"),
				MemberOf:    strings_(record, "memberof_group"),
			})
		}
		return groups, nil
	})
}

// Hosts zwraca hosty zarejestrowane w katalogu.
func (c *Client) Hosts(ctx context.Context) ([]Host, error) {
	return cached(ctx, c, "hosts", func() ([]Host, error) {
		// Tryb surowy jest tu konieczny: krbLastPwdChange, jedyny wskaznik
		// dolaczenia dostepny bez zapytania na kazdy host, jest odfiltrowany
		// z widoku przyjaznego.
		records, err := c.findRaw(ctx, "host_find")
		if err != nil {
			return nil, err
		}
		hosts := make([]Host, 0, len(records))
		for _, record := range records {
			// has_keytab jest atrybutem wyliczanym wylacznie przez host_show,
			// wiec uzycie go wymagaloby zapytania na kazdy host - dokladnie
			// tego, czego dokument zabrania. krbLastPwdChange pojawia sie
			// w chwili ustawienia klucza hosta, wiec rozroznia hosty
			// dolaczone od samych wpisow w katalogu.
			enrolledAt := first(record, "krblastpwdchange")
			hosts = append(hosts, Host{
				FQDN:        first(record, "fqdn"),
				Description: first(record, "description"),
				Enrolled:    enrolledAt != "",
				EnrolledAt:  enrolledAt,
				MemberOf:    hostGroupsFromDNs(strings_(record, "memberof")),
			})
		}
		return hosts, nil
	})
}

// HBACRules zwraca reguly dostepu.
func (c *Client) HBACRules(ctx context.Context) ([]HBACRule, error) {
	return cached(ctx, c, "hbac", func() ([]HBACRule, error) {
		records, err := c.findRecords(ctx, "hbacrule_find")
		if err != nil {
			return nil, err
		}
		rules := make([]HBACRule, 0, len(records))
		for _, record := range records {
			rule := HBACRule{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				Enabled:     boolean(record, "ipaenabledflag"),
				Users:       strings_(record, "memberuser_user"),
				UserGroups:  strings_(record, "memberuser_group"),
				Hosts:       strings_(record, "memberhost_host"),
				HostGroups:  strings_(record, "memberhost_hostgroup"),
				Services:    strings_(record, "memberservice_hbacsvc"),
			}
			// Regula obejmujaca wszystkich, wszystkie hosty i wszystkie uslugi
			// otwiera dostep do calej floty jednym wpisem.
			rule.AllowsEverything = first(record, "usercategory") == "all" &&
				first(record, "hostcategory") == "all" &&
				first(record, "servicecategory") == "all"
			rules = append(rules, rule)
		}
		return rules, nil
	})
}

// SudoRules zwraca reguly sudo wraz z oznaczeniem ryzyka.
func (c *Client) SudoRules(ctx context.Context) ([]SudoRule, error) {
	return cached(ctx, c, "sudo", func() ([]SudoRule, error) {
		records, err := c.findRecords(ctx, "sudorule_find")
		if err != nil {
			return nil, err
		}
		rules := make([]SudoRule, 0, len(records))
		for _, record := range records {
			rule := SudoRule{
				Name:        first(record, "cn"),
				Description: first(record, "description"),
				Enabled:     boolean(record, "ipaenabledflag"),
				Users:       strings_(record, "memberuser_user"),
				UserGroups:  strings_(record, "memberuser_group"),
				Hosts:       strings_(record, "memberhost_host"),
				HostGroups:  strings_(record, "memberhost_hostgroup"),
				Commands:    strings_(record, "memberallowcmd_sudocmd"),
				RunAs:       strings_(record, "ipasudorunas_user"),
				Options:     strings_(record, "ipasudoopt"),
			}
			rule.Critical, rule.CriticalReasons = sudoRisk(record, rule)
			rules = append(rules, rule)
		}
		return rules, nil
	})
}

// sudoRisk oznacza reguly o podwyzszonym ryzyku. NOPASSWD i ALL sa wymienione
// w dokumencie jako krytyczne: pierwsze znosi potwierdzenie tozsamosci,
// drugie daje pelne uprawnienia roota.
func sudoRisk(record map[string]any, rule SudoRule) (bool, []string) {
	var reasons []string
	for _, option := range rule.Options {
		if option == "!authenticate" || option == "NOPASSWD" || option == "nopasswd" {
			reasons = append(reasons, "reguła nie wymaga potwierdzenia hasłem")
			break
		}
	}
	if first(record, "cmdcategory") == "all" {
		reasons = append(reasons, "reguła obejmuje wszystkie polecenia")
	}
	if first(record, "hostcategory") == "all" {
		reasons = append(reasons, "reguła obejmuje wszystkie hosty")
	}
	if first(record, "usercategory") == "all" {
		reasons = append(reasons, "reguła obejmuje wszystkich użytkowników")
	}
	if first(record, "runasusercategory") == "all" {
		reasons = append(reasons, "reguła pozwala działać jako dowolny użytkownik")
	}
	return len(reasons) > 0, reasons
}

// findRecords wykonuje wyszukiwanie w widoku przyjaznym.
func (c *Client) findRecords(ctx context.Context, method string) ([]map[string]any, error) {
	return c.find(ctx, method, false)
}

// find wykonuje polecenie wyszukiwania i zwraca rekordy katalogu.
func (c *Client) find(ctx context.Context, method string, raw bool) ([]map[string]any, error) {
	options := map[string]any{
		"all": true,
		// Zero oznacza brak limitu po stronie serwera; katalog testowy jest
		// maly, a przy duzym trzeba bedzie stronicowac.
		"sizelimit": 0,
	}
	if raw {
		options["raw"] = true
	}
	result, err := c.call(ctx, method, []string{}, options)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Result    []map[string]any `json:"result"`
		Count     int              `json:"count"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, fmt.Errorf("odpowiedz %s: %w", method, err)
	}
	if decoded.Truncated {
		// Obciety wynik jest gorszy niz blad: wygladalby jak kompletna lista.
		return nil, fmt.Errorf("katalog obcial wynik %s; wymagane stronicowanie", method)
	}
	return decoded.Result, nil
}

// hostGroupsFromDNs wyciaga nazwy grup hostow z pelnych DN-ow. W trybie
// surowym katalog zwraca czlonkostwo jako DN, a nie jako nazwe.
func hostGroupsFromDNs(dns []string) []string {
	var groups []string
	for _, dn := range dns {
		if !strings.Contains(dn, "cn=hostgroups") {
			continue
		}
		first, _, found := strings.Cut(dn, ",")
		if !found {
			continue
		}
		if name, ok := strings.CutPrefix(first, "cn="); ok {
			groups = append(groups, name)
		}
	}
	return groups
}

// FreeIPA zwraca wartosci jako listy, nawet dla pol jednowartosciowych.
func first(record map[string]any, key string) string {
	values := strings_(record, key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// lookup znajduje wartosc niezaleznie od wielkosci liter w nazwie pola.
// Katalog zwraca raz "krbLastPwdChange", raz "krblastpwdchange", zaleznie od
// trybu odpowiedzi; przypinanie sie do jednej pisowni konczy sie cichym
// brakiem danych.
func lookup(record map[string]any, key string) any {
	if value, ok := record[key]; ok {
		return value
	}
	lower := strings.ToLower(key)
	for name, value := range record {
		if strings.ToLower(name) == lower {
			return value
		}
	}
	return nil
}

func strings_(record map[string]any, key string) []string {
	switch value := lookup(record, key).(type) {
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
				continue
			}
			// Katalog zwraca czasem obiekty {"__base64__": ...} albo liczby.
			if nested, ok := item.(map[string]any); ok {
				if text, ok := nested["__base64__"].(string); ok {
					result = append(result, text)
				}
			}
		}
		return result
	case string:
		return []string{value}
	case bool:
		return []string{fmt.Sprint(value)}
	default:
		return nil
	}
}

func boolean(record map[string]any, key string) bool {
	switch value := lookup(record, key).(type) {
	case bool:
		return value
	case []any:
		if len(value) > 0 {
			if flag, ok := value[0].(bool); ok {
				return flag
			}
			if text, ok := value[0].(string); ok {
				return text == "TRUE" || text == "true"
			}
		}
	}
	return false
}
