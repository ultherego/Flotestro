package helper

import (
	"context"
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
	if action.GetOperation() != helperv1.DnsRequest_OPERATION_APPLY {
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
		return reject(ErrorUnsupported,
			"ten host nie ma NetworkManagera; resolver jest tu tylko do odczytu")
	}

	polaczenie, profil, err := s.profilInterfejsu(actionCtx, action.GetInterface())
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
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
