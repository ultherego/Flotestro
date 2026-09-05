package adminapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/integrations"
	"github.com/ultherego/flotestro/internal/integrations/alerts"
	"github.com/ultherego/flotestro/internal/integrations/metrics"
)

// Monitoring zbiera zrodla, z ktorych panel czyta metryki i alerty.
//
// Zadne z nich nie jest wymagane: instalacja bez monitoringu dziala tak samo,
// tyle ze zakladka monitoringu mowi wprost, ze zrodel nie wskazano. Awaria
// integracji tez nie moze zabrac operatorowi zarzadzania hostem - dlatego
// kazde pytanie ma limit czasu i bezpiecznik.
type Monitoring struct {
	Metryki   metrics.Provider
	Alerty    alerts.Provider
	Mapowanie integrations.Mapowanie
}

// SetMonitoring podlacza integracje monitoringowe.
func (s *Server) SetMonitoring(monitoring Monitoring) { s.monitoring = monitoring }

// raportMonitoringu jest odpowiedzia zakladki hosta.
type raportMonitoringu struct {
	HostID string `json:"host_id"`
	// Sources opisuje stan zrodel: nieskonfigurowane, dzialajace albo takie,
	// ktore nie odpowiadaja. To trzy rozne odpowiedzi.
	Sources []integrations.Stan `json:"sources"`
	// Label mowi, po czym panel rozpoznaje ten host u zrodel. Bez tego pusty
	// wykres nie ma wyjasnienia.
	Label    string                 `json:"label"`
	Links    integrations.Odnosniki `json:"links"`
	Alerts   []alerts.Alert         `json:"alerts"`
	Silences []alerts.Cisza         `json:"silences"`
	Series   []metrics.Szereg       `json:"series"`
	// From i To opisuja zakres czasu wykresow: panel pokazuje cudze dane
	// i mowi, z jakiego okna pochodza.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// AlertsUnavailable i MetricsUnavailable mowia, dlaczego czegos nie ma.
	AlertsUnavailable  string `json:"alerts_unavailable_reason,omitempty"`
	MetricsUnavailable string `json:"metrics_unavailable_reason,omitempty"`
}

// handleHostMonitoring zwraca alerty, wykresy i odnosniki hosta.
func (s *Server) handleHostMonitoring(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermMonitoringRead, scope, "host", hostID); !ok {
		return
	}

	opis := opisHosta(*host)
	okno := s.monitoring.Mapowanie.OknoAlbo(oknoZapytania(r))
	do := time.Now().UTC()
	od := do.Add(-okno)

	raport := raportMonitoringu{
		HostID: hostID,
		Label:  s.monitoring.Mapowanie.Etykieta(opis),
		Links:  s.monitoring.Mapowanie.Dla(opis),
		From:   od, To: do,
		Alerts: []alerts.Alert{}, Silences: []alerts.Cisza{}, Series: []metrics.Szereg{},
	}
	raport.Sources = s.stanZrodel(r)

	if s.monitoring.Alerty != nil && s.monitoring.Alerty.Skonfigurowany() {
		filtr := []string{s.monitoring.Mapowanie.FiltrHosta(opis)}
		if lista, err := s.monitoring.Alerty.Alerty(r.Context(), filtr); err != nil {
			// Awaria zrodla alertow nie moze wywrocic zakladki: mowimy,
			// czego nie wiadomo, i pokazujemy reszte.
			raport.AlertsUnavailable = err.Error()
		} else if lista != nil {
			// Pusta lista zostaje pusta lista, a nie brakiem pola: interfejs
			// ma pokazac "nic sie nie pali", a nie "nie wiadomo".
			raport.Alerts = lista
		}
		if ciszy, err := s.monitoring.Alerty.Ciszy(r.Context(), filtr); err != nil {
			if raport.AlertsUnavailable == "" {
				raport.AlertsUnavailable = err.Error()
			}
		} else if ciszy != nil {
			raport.Silences = ciszy
		}
	}
	if s.monitoring.Metryki != nil && s.monitoring.Metryki.Skonfigurowany() {
		raport.Series = s.monitoring.Metryki.Szeregi(r.Context(), raport.Label, od, do)
	} else {
		raport.MetricsUnavailable = "this installation has no metrics source configured"
	}
	writeJSON(w, http.StatusOK, raport)
}

// stanZrodel pyta integracje o zdrowie.
func (s *Server) stanZrodel(r *http.Request) []integrations.Stan {
	stany := make([]integrations.Stan, 0, 2)
	if s.monitoring.Metryki != nil {
		stany = append(stany, s.monitoring.Metryki.Zdrowie(r.Context()))
	}
	if s.monitoring.Alerty != nil {
		stany = append(stany, s.monitoring.Alerty.Zdrowie(r.Context()))
	}
	return stany
}

// oknoZapytania czyta zakres czasu z zapytania.
func oknoZapytania(r *http.Request) time.Duration {
	wartosc := r.URL.Query().Get("range")
	if wartosc == "" {
		return 0
	}
	okno, err := time.ParseDuration(wartosc)
	if err != nil || okno <= 0 || okno > 7*24*time.Hour {
		return 0
	}
	return okno
}

func opisHosta(host hosts.Host) integrations.Host {
	return integrations.Host{
		ID: host.ID, Hostname: host.Hostname, Address: host.ManagementAddress,
		Site: host.Site, Environment: host.Environment,
	}
}

// zadanieCiszy opisuje wyciszenie zlecone z panelu.
type zadanieCiszy struct {
	// DurationMinutes jest terminem konca liczonym od teraz. Zero oznacza
	// czas domyslny; wyciszenia bezterminowego nie da sie tu zlecic.
	DurationMinutes int    `json:"duration_minutes,omitempty"`
	Comment         string `json:"comment"`
	// AlertName zawezaja wyciszenie do jednego alertu. Puste oznacza
	// wszystkie alerty tego hosta.
	AlertName string `json:"alert_name,omitempty"`
}

// handleCreateSilence zaklada wyciszenie alertow hosta.
//
// To nie jest operacja na hoscie i nie idzie przez opspec: zmienia to, co
// o hoscie sadzi system alertowy, a nie stan maszyny - tak samo jak okno
// serwisowe. Ale jest decyzja o wylaczeniu czujnika, wiec ma wlasne
// uprawnienie, obowiazkowy termin, obowiazkowy powod i slad w audycie.
func (s *Server) handleCreateSilence(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	host, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "host", hostID)
	if !ok {
		return
	}
	if s.monitoring.Alerty == nil || !s.monitoring.Alerty.Skonfigurowany() {
		problem(w, http.StatusServiceUnavailable, "alerts_not_configured",
			"this installation has no alert source configured")
		return
	}

	var zadanie zadanieCiszy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&zadanie); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	trwanie := time.Duration(zadanie.DurationMinutes) * time.Minute
	if trwanie <= 0 {
		trwanie = alerts.DomyslnaCisza
	}

	opis := opisHosta(*host)
	teraz := time.Now().UTC()
	cisza := alerts.Cisza{
		Matchers: []alerts.Dopasowanie{{
			Name:  s.monitoring.Mapowanie.HostLabel,
			Value: s.monitoring.Mapowanie.Etykieta(opis),
		}},
		StartsAt: teraz, EndsAt: teraz.Add(trwanie),
		CreatedBy: principal.Subject, Comment: zadanie.Comment,
	}
	if zadanie.AlertName != "" {
		cisza.Matchers = append(cisza.Matchers,
			alerts.Dopasowanie{Name: "alertname", Value: zadanie.AlertName})
	}
	if err := alerts.WalidujCisze(cisza); err != nil {
		problem(w, http.StatusBadRequest, "invalid_silence", err.Error())
		return
	}

	identyfikator, err := s.monitoring.Alerty.Ucisz(r.Context(), cisza)
	if err != nil {
		s.audit.Record(r.Context(), audit.Event{
			ActorType: audit.ActorUser, ActorID: principal.Subject,
			Action: "monitoring.silence.create", TargetType: "host", TargetID: hostID,
			RequestID: requestIDOf(r), Outcome: audit.OutcomeFailure,
			Detail: map[string]any{"reason": err.Error()},
		})
		problem(w, http.StatusBadGateway, "alerts_unavailable", err.Error())
		return
	}
	cisza.ID = identyfikator

	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.create", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"silence_id": identyfikator, "ends_at": cisza.EndsAt.Format(time.RFC3339),
			"comment": cisza.Comment, "alert_name": zadanie.AlertName,
			"label": cisza.Matchers[0].Name + "=" + cisza.Matchers[0].Value,
		},
	})
	writeJSON(w, http.StatusCreated, cisza)
}

// handleExpireSilence konczy wyciszenie przed czasem.
func (s *Server) handleExpireSilence(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermMonitoringSilence, scope, "host", hostID)
	if !ok {
		return
	}
	if s.monitoring.Alerty == nil || !s.monitoring.Alerty.Skonfigurowany() {
		problem(w, http.StatusServiceUnavailable, "alerts_not_configured",
			"this installation has no alert source configured")
		return
	}
	identyfikator := r.PathValue("silence")
	if err := s.monitoring.Alerty.Odcisz(r.Context(), identyfikator); err != nil {
		problem(w, http.StatusBadGateway, "alerts_unavailable", err.Error())
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "monitoring.silence.expire", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"silence_id": identyfikator},
	})
	w.WriteHeader(http.StatusNoContent)
}

// alertFloty laczy alert z hostem panelu.
type alertFloty struct {
	HostID   string       `json:"host_id,omitempty"`
	Hostname string       `json:"hostname,omitempty"`
	Alert    alerts.Alert `json:"alert"`
}

// handleFleetMonitoring zwraca alerty calej widocznej floty.
//
// Alerty dzialaja flotowo z natury: jedna zla zmiana widac naraz na
// kilkudziesieciu hostach. Panel dokłada do nich to, czego system alertowy
// nie wie - ktory host z floty to jest i czy wolno go temu operatorowi
// pokazac.
func (s *Server) handleFleetMonitoring(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermMonitoringRead, "fleet")
	if !ok {
		return
	}
	odpowiedz := map[string]any{
		"sources": s.stanZrodel(r),
		"items":   []alertFloty{},
	}
	if s.monitoring.Alerty == nil || !s.monitoring.Alerty.Skonfigurowany() {
		odpowiedz["alerts_unavailable_reason"] = "this installation has no alert source configured"
		writeJSON(w, http.StatusOK, odpowiedz)
		return
	}

	lista, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	poEtykiecie := map[string]hosts.Host{}
	for _, host := range lista {
		if principal.Can(authz.PermMonitoringRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			poEtykiecie[s.monitoring.Mapowanie.Etykieta(opisHosta(host))] = host
		}
	}

	wszystkie, err := s.monitoring.Alerty.Alerty(r.Context(), nil)
	if err != nil {
		odpowiedz["alerts_unavailable_reason"] = err.Error()
		writeJSON(w, http.StatusOK, odpowiedz)
		return
	}

	pozycje := make([]alertFloty, 0, len(wszystkie))
	obce := 0
	for _, alert := range wszystkie {
		etykieta := alert.Labels[s.monitoring.Mapowanie.HostLabel]
		host, znany := poEtykiecie[etykieta]
		if !znany {
			// Alert spoza floty albo z hosta, ktorego ten operator nie
			// widzi. Nie pokazujemy go, ale liczymy: cisza w tym miejscu
			// wygladalaby jak spokojna flota.
			obce++
			continue
		}
		pozycje = append(pozycje, alertFloty{
			HostID: host.ID, Hostname: host.Hostname, Alert: alert,
		})
	}
	// Najpierw najciezsze, potem najstarsze: tak sie czyta dyzur.
	sort.SliceStable(pozycje, func(i, j int) bool {
		if pozycje[i].Alert.Severity != pozycje[j].Alert.Severity {
			return wagaWagi(pozycje[i].Alert.Severity) > wagaWagi(pozycje[j].Alert.Severity)
		}
		if pozycje[i].Alert.StartsAt == nil || pozycje[j].Alert.StartsAt == nil {
			return pozycje[i].Hostname < pozycje[j].Hostname
		}
		return pozycje[i].Alert.StartsAt.Before(*pozycje[j].Alert.StartsAt)
	})

	odpowiedz["items"] = pozycje
	odpowiedz["hosts_visible"] = len(poEtykiecie)
	odpowiedz["alerts_outside_fleet"] = obce
	odpowiedz["host_label"] = s.monitoring.Mapowanie.HostLabel
	writeJSON(w, http.StatusOK, odpowiedz)
}

// wagaWagi porzadkuje alerty wedlug tego, jak pilne sa dla dyzuru.
func wagaWagi(waga string) int {
	switch waga {
	case "critical", "page":
		return 3
	case "warning":
		return 2
	case "info", "none":
		return 1
	}
	return 0
}
