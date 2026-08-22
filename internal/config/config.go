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
