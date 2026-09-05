// Package config zbiera konfiguracje control plane i agenta ze zmiennych
// srodowiskowych oraz flag.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ControlPlane opisuje konfiguracje serwera.
type ControlPlane struct {
	DatabaseURL      string
	StateDir         string
	GatewayAddr      string
	EnrollmentAddr   string
	AdminAddr        string
	AdvertisedHosts  []string
	HeartbeatSeconds int
	HeartbeatJitter  int
	StaleAfter       time.Duration
	GatewayID        string
}

// Monitoring opisuje polaczenia z systemami metryk i alertow.
//
// Kazde jest opcjonalne: instalacja bez monitoringu dziala tak samo, a panel
// mowi wprost, ze zrodel nie wskazano - zamiast rysowac puste wykresy.
type Monitoring struct {
	PrometheusURL   string
	AlertmanagerURL string
	Timeout         time.Duration
	// HostLabel i HostValue tlumacza host panelu na etykiete u zrodel.
	HostLabel        string
	HostValue        string
	SiteLabel        string
	EnvironmentLabel string
	// DashboardURL i LogsURL sa szablonami odnosnikow: panel prowadzi do
	// cudzych ekranow, zamiast je odtwarzac.
	DashboardURL string
	LogsURL      string
	Window       time.Duration
}

// Podatnosci opisuje korelator CVE.
//
// Rozstrzyga tracker producenta dystrybucji; feedy upstreamowe moga pozniej
// dolozyc opis i CVSS, ale nie moga zmienic odpowiedzi "podatny / niepodatny".
type Podatnosci struct {
	Enabled bool
	// SyncInterval mowi, jak czesto panel pyta trackery o zmiany.
	SyncInterval time.Duration
	// MaxSnapshotAge jest wiekiem, powyzej ktorego dane sa nieswieze. Nie
	// zatrzymuje to oceny, ale musi byc widoczne obok wyniku.
	MaxSnapshotAge time.Duration
	// DebianURL wskazuje zrzut trackera Debiana; pusty wylacza to zrodlo.
	DebianURL string
}

// Env odczytuje zmienna srodowiskowa z wartoscia domyslna.
func Env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

// EnvInt odczytuje liczbowa zmienna srodowiskowa.
func EnvInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

// EnvDuration odczytuje zmienna srodowiskowa wyrazona czasem, na przyklad
// "5m". Wartosc nieczytelna nie moze cicho wylaczyc zabezpieczenia, wiec
// zostaje wartosc domyslna.
func EnvDuration(key string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

// Validate sprawdza minimalny zestaw wymaganych ustawien.
func (c ControlPlane) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("brak FLOTESTRO_DATABASE_URL")
	}
	if c.StateDir == "" {
		return fmt.Errorf("brak katalogu stanu")
	}
	return nil
}
