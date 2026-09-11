package helper

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/network"
)

// applyDNS zmienia resolver hosta przez profil polaczenia.
//
// Nie piszemy do /etc/resolv.conf: plik nalezacy do resolved albo
// NetworkManagera zostanie nadpisany przy nastepnym zdarzeniu sieci, wiec
// zapis w nim bylby zmiana, ktora znika sama - i to bez sladu.
//
// Zmiana jest uzbrajana wycofaniem tak samo jak zmiana adresu: host bez
// dzialajacego resolvera traci katalog, Kerberosa i logowanie, wiec skutek
// bledu siega dalej niz jedna nierozwiazana nazwa.
func (s *Server) applyDNS(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.DnsRequest) *helperv1.HelperResponse {
	planowanie := action.GetOperation() == helperv1.DnsRequest_OPERATION_PLAN
	if !planowanie && action.GetOperation() != helperv1.DnsRequest_OPERATION_APPLY {
		return reject(ErrorUnknownAction, "nieznana operacja na resolverze")
	}
	if !s.unitMutex.TryLock() {
		return reject(ErrorLocked, "inna operacja na jednostkach jest w toku")
	}
	defer s.unitMutex.Unlock()

	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !network.Istnieje(network.SciezkaNmcli) {
		powod := "ten host nie ma NetworkManagera; resolver jest tu tylko do odczytu"
		if planowanie {
			// Brak mechanizmu zapisu jest odpowiedzia planu, nie bledem
			// odczytu: kampania ma zobaczyc ten host jako odmowe.
			return odpowiedzPlanuResolvera(nil,
				network.OdmowaPlanu(action.GetInterface(), network.PlanDNS, powod))
		}
		return reject(ErrorUnsupported, powod)
	}

	polaczenie, profil, err := s.profilInterfejsu(actionCtx, action.GetInterface())
	if err != nil {
		if planowanie {
			return odpowiedzPlanuResolvera(s.czytajProfile(actionCtx),
				network.OdmowaPlanu(action.GetInterface(), network.PlanDNS, err.Error()))
		}
		return reject(ErrorUnsupported, err.Error())
	}

	if planowanie {
		return odpowiedzPlanuResolvera(s.czytajProfile(actionCtx), planResolvera(action, profil))
	}
	// Zmiana zatwierdzona na podstawie planu ma wejsc w ten stan, ktory
	// operator ogladal. Inny odcisk znaczy, ze profil zmienil sie od
	// planowania - i to jest odmowa, nie ostrzezenie.
	if oczekiwany := action.GetPlanHash(); oczekiwany != "" {
		if teraz := planResolvera(action, profil); teraz.PlanHash != oczekiwany {
			return reject(ErrorPreconditionFailed,
				"profil "+polaczenie+" zmienil sie od planowania; zmiana wymaga nowego planu")
		}
	}

	kroki, err := network.ArgumentyDNS(polaczenie, action.GetServers(),
		action.GetSearchDomains(), action.GetIgnoreAutoDns())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	plan := network.PlanWycofania{
		ID:        identyfikatorWycofania(),
		Profil:    profil,
		Interfejs: action.GetInterface(),
		Utworzony: time.Now().UTC(),
	}
	okno := oknoWycofania(action.GetRollbackSeconds())
	plan.Termin = plan.Utworzony.Add(okno)
	if _, err := network.KrokiWycofania(plan); err != nil {
		return reject(ErrorUnsupported, "nie da sie zlozyc wycofania: "+err.Error())
	}
	if err := network.ZapiszPlan(network.KatalogWycofan, plan); err != nil {
		return reject(ErrorExecFailed, "zapis planu wycofania: "+err.Error())
	}
	if err := s.uzbrojWycofanie(actionCtx, plan, okno); err != nil {
		_ = network.UsunPlan(network.KatalogWycofan, plan.ID)
		return reject(ErrorExecFailed, "uzbrojenie wycofania: "+err.Error())
	}

	for _, krok := range kroki {
		if wyjscie, err := uruchomNmcli(actionCtx, krok); err != nil {
			odpowiedz := reject(ErrorExecFailed, err.Error()+": "+wyjscie)
			odpowiedz.DnsResult = &helperv1.DnsResult{
				Message:          wyjscie,
				RollbackId:       plan.ID,
				RollbackDeadline: plan.Termin.Format(time.RFC3339),
			}
			return odpowiedz
		}
	}

	profile := s.czytajProfile(actionCtx)
	zakodowane, err := zakodujProfile(profile)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DnsResult: &helperv1.DnsResult{
			Profiles: zakodowane,
			Message: "resolver zmieniony; wycofanie o " +
				plan.Termin.Format(time.RFC3339) + ", jesli agent nie potwierdzi lacznosci",
			RollbackId:       plan.ID,
			RollbackDeadline: plan.Termin.Format(time.RFC3339),
		},
	}
}

// planResolvera liczy plan zmiany resolvera wobec profilu zastanego.
func planResolvera(action *helperv1.DnsRequest, profil network.Profil) network.Plan {
	return network.ZaplanujDNS(action.GetInterface(), profil, action.GetServers(),
		action.GetSearchDomains(), action.GetIgnoreAutoDns())
}

func odpowiedzPlanuResolvera(profile []network.Profil, plan network.Plan) *helperv1.HelperResponse {
	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	zakodowane, err := zakodujProfile(profile)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "zmiana nie wejdzie na ten host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == network.PlanBezZmian:
		komunikat = "resolver profilu " + plan.Connection + " jest juz w stanie docelowym"
	default:
		komunikat = "resolver profilu " + plan.Connection + ": " + strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		DnsResult: &helperv1.DnsResult{
			Profiles: zakodowane, Message: komunikat, Plan: zakodowany,
		},
	}
}
