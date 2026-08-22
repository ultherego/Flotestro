package agent

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// IdentityState opisuje integracje hosta z domena. Zbierany jest w cyklu
// inventory, nigdy przy heartbeacie: odpytywanie katalogu kilka razy na minute
// z kazdego hosta floty byloby dokladnie tym obciazeniem, przed ktorym broni
// sie dokument.
type IdentityState struct {
	Enrolled bool     `json:"enrolled"`
	Domain   string   `json:"domain,omitempty"`
	Realm    string   `json:"realm,omitempty"`
	Servers  []string `json:"servers,omitempty"`

	SSSDInstalled bool  `json:"sssd_installed"`
	SSSDRunning   bool  `json:"sssd_running"`
	SSSDOnline    *bool `json:"sssd_online,omitempty"`

	CacheAgeSeconds *uint64 `json:"cache_age_seconds,omitempty"`

	HostPrincipal    string   `json:"host_principal,omitempty"`
	KeytabKVNO       *uint32  `json:"keytab_kvno,omitempty"`
	ClockSkewSeconds *float64 `json:"clock_skew_seconds,omitempty"`
	TimeSynchronized bool     `json:"time_synchronized"`

	ConfigIssues      []string `json:"config_issues,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}

const ipaConfigPath = "/etc/ipa/default.conf"

// ReadIdentityState zbiera stan domeny lokalnie. Zadne zapytanie nie idzie do
// serwera katalogu: interesuje nas stan hosta, a nie zawartosc katalogu.
//
// Keytab hosta i baza cache SSSD sa czytelne wylacznie dla roota, wiec ta
// czesc idzie przez helpera. Agent nie ma do nich dostepu i nie powinien go
// miec: odczyt keytab to material uwierzytelniajacy hosta.
func ReadIdentityState(ctx context.Context) IdentityState {
	state := IdentityState{
		SSSDInstalled: exists("/usr/sbin/sssd") || exists("/usr/lib/systemd/system/sssd.service"),
	}

	config := parseIPAConfig()
	state.Enrolled = len(config) > 0
	state.Domain = config["domain"]
	state.Realm = config["realm"]
	if server := config["server"]; server != "" {
		state.Servers = append(state.Servers, server)
	}
	if !state.Enrolled {
		// Host poza domena to poprawny stan, a nie brak danych.
		return state
	}

	state.SSSDRunning = unitActive(ctx, "sssd.service")
	state.ClockSkewSeconds, state.TimeSynchronized = clockState(ctx)
	return state
}

// PrivilegedIdentity uzupelnia stan o dane wymagajace roota.
type PrivilegedIdentity struct {
	HostPrincipal     string
	KeytabKVNO        *uint32
	CacheAgeSeconds   *uint64
	SSSDOnline        *bool
	ConfigIssues      []string
	UnavailableReason string
}

// Merge dolacza wynik z helpera do stanu odczytanego bez uprawnien.
func (s IdentityState) Merge(privileged PrivilegedIdentity) IdentityState {
	s.HostPrincipal = privileged.HostPrincipal
	s.KeytabKVNO = privileged.KeytabKVNO
	s.CacheAgeSeconds = privileged.CacheAgeSeconds
	s.SSSDOnline = privileged.SSSDOnline
	s.ConfigIssues = privileged.ConfigIssues
	s.UnavailableReason = privileged.UnavailableReason
	return s
}

// parseIPAConfig czyta /etc/ipa/default.conf. Obecnosc pliku jest jedynym
// pewnym lokalnym dowodem, ze host zostal dolaczony do domeny.
func parseIPAConfig() map[string]string {
	file, err := os.Open(ipaConfigPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	config := map[string]string{}
	for line := range iterLines(ipaConfigPath) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		config[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return config
}

func unitActive(ctx context.Context, unit string) bool {
	result := runCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "is-active", "--quiet", unit)
	return result.Ran && result.ExitCode == 0
}

// sssdOnline pyta SSSD o stan polaczenia z domena. Kod niezerowy bez wyniku

// sssdCacheAge zwraca wiek pliku cache. Rosnacy wiek przy hoscie offline

// hostKeytab odczytuje principal hosta i numer wersji klucza. Rozjazd KVNO

// clockState czyta rozjazd zegara. Kerberos przestaje dzialac przy roznicy
// rzedu minut, wiec ta wartosc jest wczesnym ostrzezeniem.
func clockState(ctx context.Context) (skew *float64, synchronized bool) {
	result := runCommand(ctx, 15*time.Second, "/usr/bin/chronyc", "-c", "tracking")
	if !result.Ran || result.ExitCode != 0 {
		return nil, false
	}
	// Format -c to wartosci rozdzielone przecinkami; pole 5 to odchylenie
	// systemowe w sekundach, a pole 1 to adres zrodla.
	fields := strings.Split(strings.TrimSpace(result.Stdout), ",")
	if len(fields) < 6 {
		return nil, false
	}
	if parsed, err := strconv.ParseFloat(fields[4], 64); err == nil {
		skew = &parsed
	}
	synchronized = fields[1] != "" && fields[1] != "0.0.0.0"
	return skew, synchronized
}
