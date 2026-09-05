package integrations

import (
	"strings"
	"time"
)

// Mapowanie tlumaczy hosta z panelu na etykiety w systemach monitoringu.
//
// To jest cala trudnosc tej integracji: panel zna host po identyfikatorze
// i nazwie, Prometheus po etykiecie "instance", ktora zwykle jest adresem
// z portem exportera, a Alertmanager po tym, co akurat wpisano w regule.
// Zgadywanie konczy sie pustym wykresem bez wyjasnienia, wiec mapowanie jest
// jawne, konfigurowalne i pokazywane operatorowi razem z wynikiem.
type Mapowanie struct {
	// HostLabel jest nazwa etykiety, ktora identyfikuje host.
	HostLabel string
	// HostValue jest szablonem wartosci tej etykiety.
	HostValue string
	// SiteLabel i EnvironmentLabel sa opcjonalne: uzywamy ich w widoku floty
	// i przy wyciszeniach obejmujacych wiecej niz jeden host.
	SiteLabel        string
	EnvironmentLabel string
	// DashboardURL i LogsURL sa szablonami odnosnikow. Panel nie rysuje
	// cudzych dashboardow - prowadzi do nich.
	DashboardURL string
	LogsURL      string
	// Okno jest domyslnym zakresem czasu wykresow.
	Okno time.Duration
}

// Host opisuje host w jezyku panelu.
type Host struct {
	ID          string
	Hostname    string
	Address     string
	Site        string
	Environment string
}

// DomyslneMapowanie odpowiada instalacji z node_exporterem na porcie 9100.
//
// Domyslne, a nie jedyne: instalacja, ktora nazywa hosty inaczej, podmienia
// szablon w konfiguracji zamiast dostawac puste wykresy.
func DomyslneMapowanie() Mapowanie {
	return Mapowanie{
		HostLabel:        "instance",
		HostValue:        "{hostname}:9100",
		SiteLabel:        "site",
		EnvironmentLabel: "environment",
		Okno:             3 * time.Hour,
	}
}

// Etykieta zwraca wartosc etykiety hosta.
func (m Mapowanie) Etykieta(host Host) string {
	return m.Podstaw(m.HostValue, host)
}

// Podstaw wstawia w szablon dane hosta.
//
// Pola, ktorych szablon nie uzywa, po prostu nie wystepuja; pola puste
// zostawiamy puste, zamiast wstawiac slowo "unknown" - odnosnik z takim
// slowem prowadzilby do wykresu, ktorego nie ma.
func (m Mapowanie) Podstaw(szablon string, host Host) string {
	zamiany := []string{
		"{hostname}", host.Hostname,
		"{host_id}", host.ID,
		"{address}", host.Address,
		"{site}", host.Site,
		"{environment}", host.Environment,
	}
	return strings.NewReplacer(zamiany...).Replace(szablon)
}

// FiltrHosta zwraca filtr Alertmanagera dla jednego hosta.
func (m Mapowanie) FiltrHosta(host Host) string {
	return m.HostLabel + `="` + m.Etykieta(host) + `"`
}

// Odnosniki opisuja, dokad panel prowadzi po szczegoly.
type Odnosniki struct {
	Dashboard string `json:"dashboard,omitempty"`
	Logs      string `json:"logs,omitempty"`
}

// Dla zwraca odnosniki dla hosta.
func (m Mapowanie) Dla(host Host) Odnosniki {
	odnosniki := Odnosniki{}
	if m.DashboardURL != "" {
		odnosniki.Dashboard = m.Podstaw(m.DashboardURL, host)
	}
	if m.LogsURL != "" {
		odnosniki.Logs = m.Podstaw(m.LogsURL, host)
	}
	return odnosniki
}

// OknoAlbo zwraca zakres czasu wykresu.
func (m Mapowanie) OknoAlbo(zadane time.Duration) time.Duration {
	if zadane > 0 {
		return zadane
	}
	if m.Okno > 0 {
		return m.Okno
	}
	return 3 * time.Hour
}
