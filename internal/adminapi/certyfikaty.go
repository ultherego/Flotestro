package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	certyfikaty "github.com/ultherego/flotestro/internal/certificates"
	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	modul "github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/secrets"
)

// certyfikatWidok laczy to, co widzi host, z tym, co panel o pliku wie.
//
// Sam certyfikat nie odpowiada na pytanie operatora. Pytanie brzmi: czy to,
// co lezy na hoscie, jest tym, co panel tam polozyl, kto to odnowi i co sie
// zepsuje, gdy termin minie. Dopiero polaczenie obserwacji hosta, zakresu
// obserwacji i historii wdrozen na to odpowiada.
type certyfikatWidok struct {
	modul.Certyfikat
	// Status jest ocena panelu, a nie faktem z hosta.
	Status string `json:"status"`
	// DaysToExpiry moze byc ujemne: certyfikat wygasly ma opisywac, jak
	// dawno, a nie zerowac sie do "0 dni".
	DaysToExpiry *int `json:"days_to_expiry,omitempty"`
	// Watched mowi, ze panel pilnuje tego pliku z wlasnej konfiguracji.
	Watched bool `json:"watched"`
	// Managed mowi, ze ten konkretny certyfikat wdrozyl panel: odcisk
	// z historii zgadza sie z odciskiem z hosta.
	Managed bool `json:"managed"`
	// DeployedAt i DeployedBy opisuja ostatnie wdrozenie tego pliku z panelu.
	DeployedAt *time.Time `json:"deployed_at,omitempty"`
	DeployedBy string     `json:"deployed_by,omitempty"`
	// KeySecret jest nazwa sekretu z kluczem. Nazwa, nie wartosc.
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`
}

// raportCertyfikatow jest odpowiedzia zakladki hosta.
type raportCertyfikatow struct {
	HostID       string            `json:"host_id"`
	Certificates []certyfikatWidok `json:"certificates"`
	// Targets wylicza zakres obserwacji panelu. Cel bez obserwacji jest
	// osobna wiadomoscia: panel pilnuje pliku, ktorego host jeszcze nie
	// zglosil - najczesciej dlatego, ze nikt nie zlecil skanu.
	Targets []certyfikaty.Cel `json:"targets"`
	Status  string            `json:"status"`
	// TrackingKnown i KeysKnown mowia, czego nie udalo sie ustalic.
	TrackingKnown     bool              `json:"tracking_known"`
	TrackingReason    string            `json:"tracking_reason,omitempty"`
	KeysKnown         bool              `json:"keys_known"`
	Missing           map[string]string `json:"missing,omitempty"`
	ObservedAt        *time.Time        `json:"observed_at,omitempty"`
	Revision          string            `json:"revision,omitempty"`
	Stale             bool              `json:"stale"`
	UnavailableReason string            `json:"unavailable_reason,omitempty"`
}

// handleHostCertificates zwraca certyfikaty hosta wraz z ocena terminow.
func (s *Server) handleHostCertificates(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermCertificateRead, scope, "host", hostID); !ok {
		return
	}

	cele, err := s.certyfikaty.Cele(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	wdrozenia, err := s.certyfikaty.Ostatnie(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	fragment, err := s.inventory.Fragment(r.Context(), hostID, "certificates")
	if err != nil {
		s.fail(w, err)
		return
	}

	raport := zlozRaportCertyfikatow(hostID, fragment, cele, wdrozenia, time.Now().UTC())
	writeJSON(w, http.StatusOK, raport)
}

// zlozRaportCertyfikatow laczy obserwacje hosta z wiedza panelu.
func zlozRaportCertyfikatow(hostID string, fragment *inventory.Fragment,
	cele []certyfikaty.Cel, wdrozenia map[string]certyfikaty.Wdrozenie,
	teraz time.Time) raportCertyfikatow {
	// Pusty stan oznacza hosta, ktorego certyfikatow nikt jeszcze nie
	// wskazal: panel nie ocenia czegos, o co nie zapytano.
	raport := raportCertyfikatow{HostID: hostID, Targets: cele}
	if raport.Targets == nil {
		raport.Targets = []certyfikaty.Cel{}
	}
	raport.Certificates = []certyfikatWidok{}

	obserwowane := map[string]certyfikaty.Cel{}
	for _, cel := range cele {
		obserwowane[cel.Path] = cel
	}

	var snapshot modul.Snapshot
	if fragment != nil {
		raport.Revision = fragment.Revision
		raport.UnavailableReason = fragment.UnavailableReason
		if len(fragment.Payload) > 0 {
			_ = json.Unmarshal(fragment.Payload, &snapshot)
		}
		obserwacja := fragment.ObservedAt.UTC()
		raport.ObservedAt = &obserwacja
		raport.Stale = certyfikaty.Nieswiezy(obserwacja, teraz)
	} else {
		// Brak fragmentu nie jest pusta lista certyfikatow: to host, ktorego
		// jeszcze o nie nie zapytano.
		raport.Stale = true
	}

	raport.TrackingKnown = snapshot.TrackingKnown
	raport.TrackingReason = snapshot.TrackingReason
	raport.KeysKnown = snapshot.KeysKnown
	raport.Missing = snapshot.Missing

	for _, certyfikat := range snapshot.Certificates {
		widok := certyfikatWidok{Certyfikat: certyfikat}
		widok.Status = certyfikaty.Stan(certyfikat.NotAfter, teraz)
		if certyfikat.UnavailableReason != "" {
			widok.Status = certyfikaty.StanNieznany
		}
		widok.DaysToExpiry = certyfikat.DniDoWygasniecia(teraz)
		if cel, pilnowany := obserwowane[certyfikat.Path]; pilnowany {
			widok.Watched = true
			widok.KeySecret = cel.KeySecret
			widok.ReloadUnit = cel.ReloadUnit
			widok.ProbeTarget = cel.ProbeTarget
			if widok.OwnerService == "" {
				widok.OwnerService = cel.Service
			}
		}
		if wdrozenie, wdrozony := wdrozenia[certyfikat.Path]; wdrozony {
			czas := wdrozenie.DeployedAt.UTC()
			widok.DeployedAt = &czas
			widok.DeployedBy = wdrozenie.DeployedBy
			// Wdrozenie z panelu i plik na hoscie to dwie rozne rzeczy:
			// certyfikat podmieniony poza panelem ma inny odcisk, a wiersz
			// w historii zostaje. Dlatego porownujemy odciski.
			if wdrozenie.FingerprintSHA256 == certyfikat.FingerprintSHA256 {
				widok.Managed = true
				widok.Source = modul.ZrodloPanel
			}
		}
		raport.Status = certyfikaty.Gorszy(raport.Status, widok.Status)
		raport.Certificates = append(raport.Certificates, widok)
	}

	// Cel, ktorego host nie zglosil, jest stanem nieznanym, a nie brakiem
	// problemu: plik moze nie istniec, moze byc nieczytelny, a skan mogl
	// nigdy nie pojsc.
	zaobserwowane := map[string]bool{}
	for _, certyfikat := range snapshot.Certificates {
		zaobserwowane[certyfikat.Path] = true
	}
	for _, cel := range cele {
		if zaobserwowane[cel.Path] {
			continue
		}
		raport.Certificates = append(raport.Certificates, certyfikatWidok{
			Certyfikat: modul.Certyfikat{
				Path:              cel.Path,
				OwnerService:      cel.Service,
				Source:            modul.ZrodloZewnetrzne,
				Renewal:           modul.OdnawianieNieznane,
				UnavailableReason: "the host has not reported this file yet; scan it",
			},
			Status: certyfikaty.StanNieznany, Watched: true,
			KeySecret: cel.KeySecret, ReloadUnit: cel.ReloadUnit, ProbeTarget: cel.ProbeTarget,
		})
		raport.Status = certyfikaty.Gorszy(raport.Status, certyfikaty.StanNieznany)
	}

	sort.SliceStable(raport.Certificates, func(i, j int) bool {
		return raport.Certificates[i].Path < raport.Certificates[j].Path
	})
	return raport
}

// zadanieObserwacji opisuje plik, ktorego panel ma pilnowac.
type zadanieObserwacji struct {
	Path        string `json:"path"`
	KeyPath     string `json:"key_path,omitempty"`
	KeySecret   string `json:"key_secret,omitempty"`
	ReloadUnit  string `json:"reload_unit,omitempty"`
	ProbeTarget string `json:"probe_target,omitempty"`
	Service     string `json:"service,omitempty"`
	Note        string `json:"note,omitempty"`
}

// handleWatchCertificate zaklada albo aktualizuje obserwowany plik.
//
// To nie jest operacja na hoscie i nie idzie przez opspec: zmienia to, czego
// panel pilnuje, a nie stan maszyny. Host dowiaduje sie o zmianie przy
// najblizszym skanie - i dopiero wtedy odpowiada, co pod ta sciezka lezy.
func (s *Server) handleWatchCertificate(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermCertificateWatch, scope, "host", hostID)
	if !ok {
		return
	}

	var zadanie zadanieObserwacji
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&zadanie); err != nil {
		problem(w, http.StatusBadRequest, "invalid_body", "the request body is not valid JSON")
		return
	}
	// Ta sama regula, ktora obowiazuje host: sciezka poza katalogami
	// certyfikatow nie stanie sie dozwolona przez to, ze ktos ja tu wpisal.
	if err := modul.WalidujSciezke(zadanie.Path); err != nil {
		problem(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	if zadanie.KeyPath != "" {
		if err := modul.WalidujSciezke(zadanie.KeyPath); err != nil {
			problem(w, http.StatusBadRequest, "invalid_key_path", err.Error())
			return
		}
	}
	if err := modul.WalidujJednostke(zadanie.ReloadUnit); err != nil {
		problem(w, http.StatusBadRequest, "invalid_unit", err.Error())
		return
	}
	if err := modul.WalidujCel(zadanie.ProbeTarget); err != nil {
		problem(w, http.StatusBadRequest, "invalid_probe_target", err.Error())
		return
	}
	// Sekret wskazany w konfiguracji musi istniec: inaczej blad wyszedlby
	// dopiero przy wdrozeniu, czyli w najgorszym momencie.
	if zadanie.KeySecret != "" {
		if s.secrets == nil {
			problem(w, http.StatusServiceUnavailable, "secrets_disabled",
				"this installation has no secret store")
			return
		}
		if _, err := s.secrets.Sekret(r.Context(), zadanie.KeySecret); errors.Is(err, secrets.ErrNotFound) {
			problem(w, http.StatusBadRequest, "secret_not_found", "no secret named "+zadanie.KeySecret)
			return
		} else if err != nil {
			s.fail(w, err)
			return
		}
	}

	cel, err := s.certyfikaty.Ustaw(r.Context(), certyfikaty.Cel{
		HostID: hostID, Path: zadanie.Path, KeyPath: zadanie.KeyPath,
		KeySecret: zadanie.KeySecret, ReloadUnit: zadanie.ReloadUnit,
		ProbeTarget: zadanie.ProbeTarget, Service: zadanie.Service, Note: zadanie.Note,
		UpdatedBy: principal.Subject,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "certificate.watch", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"path": cel.Path, "key_secret": cel.KeySecret, "reload_unit": cel.ReloadUnit,
		},
	})
	writeJSON(w, http.StatusOK, cel)
}

// handleUnwatchCertificate konczy obserwacje pliku.
func (s *Server) handleUnwatchCertificate(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	principal, ok := s.authorize(w, r, authz.PermCertificateWatch, scope, "host", hostID)
	if !ok {
		return
	}
	sciezka := r.URL.Query().Get("path")
	if sciezka == "" {
		problem(w, http.StatusBadRequest, "path_required", "path query parameter is required")
		return
	}
	err := s.certyfikaty.Usun(r.Context(), hostID, sciezka)
	if errors.Is(err, certyfikaty.ErrNieZnaleziono) {
		problem(w, http.StatusNotFound, "target_not_found", "the panel does not watch that path")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Event{
		ActorType: audit.ActorUser, ActorID: principal.Subject,
		Action: "certificate.unwatch", TargetType: "host", TargetID: hostID,
		RequestID: requestIDOf(r), Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{"path": sciezka},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleCertificateDeployments zwraca historie wdrozen na hoscie.
func (s *Server) handleCertificateDeployments(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	_, scope, ok := s.hostScope(w, r, hostID)
	if !ok {
		return
	}
	if _, ok := s.authorize(w, r, authz.PermCertificateRead, scope, "host", hostID); !ok {
		return
	}
	wdrozenia, err := s.certyfikaty.Wdrozenia(r.Context(), hostID, r.URL.Query().Get("path"), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	if wdrozenia == nil {
		wdrozenia = []certyfikaty.Wdrozenie{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": wdrozenia, "count": len(wdrozenia)})
}

// LimitCertyfikatowFloty ogranicza liste na ekranie floty. Liczby sa dokladne;
// lista jest probka, zeby ekran nie stal sie wydrukiem inwentarza.
const LimitCertyfikatowFloty = 100

// certyfikatFloty opisuje jeden certyfikat w skali floty.
type certyfikatFloty struct {
	HostID       string     `json:"host_id"`
	Hostname     string     `json:"hostname"`
	Path         string     `json:"path"`
	Subject      string     `json:"subject,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	DaysToExpiry *int       `json:"days_to_expiry,omitempty"`
	Status       string     `json:"status"`
	Renewal      string     `json:"renewal"`
	Service      string     `json:"owner_service,omitempty"`
	Reason       string     `json:"unavailable_reason,omitempty"`
}

// handleFleetCertificates zwraca terminy certyfikatow calej widocznej floty.
//
// To jest podstawowy tryb tego modulu. Certyfikat wygasa cicho i zawsze
// w najgorszym momencie; jedyna obrona jest lista, na ktorej wszystkie terminy
// stoja obok siebie, posortowane od najblizszego.
func (s *Server) handleFleetCertificates(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authorizeCollection(w, r, authz.PermCertificateRead, "fleet")
	if !ok {
		return
	}
	lista, err := s.hosts.List(r.Context(), hosts.ListFilter{Limit: 500})
	if err != nil {
		s.fail(w, err)
		return
	}
	widoczne := make([]hosts.Host, 0, len(lista))
	identyfikatory := make([]string, 0, len(lista))
	for _, host := range lista {
		if principal.Can(authz.PermCertificateRead, authz.Scope{Site: host.Site, Environment: host.Environment}) {
			widoczne = append(widoczne, host)
			identyfikatory = append(identyfikatory, host.ID)
		}
	}
	fragmenty, err := s.inventory.FragmentyHostow(r.Context(), identyfikatory)
	if err != nil {
		s.fail(w, err)
		return
	}

	teraz := time.Now().UTC()
	pozycje := make([]certyfikatFloty, 0, len(widoczne))
	liczby := map[string]int{}
	bezObserwacji := 0

	for _, host := range widoczne {
		fragment := fragmentModulu(fragmenty[host.ID], "certificates")
		if fragment == nil {
			bezObserwacji++
			continue
		}
		var snapshot modul.Snapshot
		if len(fragment.Payload) > 0 {
			_ = json.Unmarshal(fragment.Payload, &snapshot)
		}
		if len(snapshot.Certificates) == 0 {
			bezObserwacji++
			continue
		}
		for _, certyfikat := range snapshot.Certificates {
			stan := certyfikaty.Stan(certyfikat.NotAfter, teraz)
			if certyfikat.UnavailableReason != "" {
				stan = certyfikaty.StanNieznany
			}
			liczby[stan]++
			pozycja := certyfikatFloty{
				HostID: host.ID, Hostname: host.Hostname, Path: certyfikat.Path,
				Subject: certyfikat.Subject, Issuer: certyfikat.Issuer,
				DaysToExpiry: certyfikat.DniDoWygasniecia(teraz), Status: stan,
				Renewal: certyfikat.Renewal, Service: certyfikat.OwnerService,
				Reason: certyfikat.UnavailableReason,
			}
			pozycja.NotAfter = certyfikat.NotAfter
			pozycje = append(pozycje, pozycja)
		}
	}

	// Sortujemy od najblizszego terminu; certyfikat bez terminu idzie na
	// koniec, bo jego problem jest inny: nie wiadomo, co tam lezy.
	sort.SliceStable(pozycje, func(i, j int) bool {
		if (pozycje[i].NotAfter == nil) != (pozycje[j].NotAfter == nil) {
			return pozycje[j].NotAfter == nil
		}
		if pozycje[i].NotAfter == nil {
			return pozycje[i].Hostname < pozycje[j].Hostname
		}
		return pozycje[i].NotAfter.Before(*pozycje[j].NotAfter)
	})
	obciete := false
	if len(pozycje) > LimitCertyfikatowFloty {
		pozycje = pozycje[:LimitCertyfikatowFloty]
		obciete = true
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": pozycje, "counts": liczby, "truncated": obciete,
		"hosts_total": len(widoczne), "hosts_without_certificates": bezObserwacji,
		"thresholds": map[string]int{
			"critical_days": int(certyfikaty.ProgPilny.Hours() / 24),
			"warning_days":  int(certyfikaty.ProgOstrzezenia.Hours() / 24),
		},
	})
}

// fragmentModulu wybiera fragment jednego modulu z listy fragmentow hosta.
func fragmentModulu(fragmenty []inventory.Fragment, modul string) *inventory.Fragment {
	for i := range fragmenty {
		if fragmenty[i].Module == modul {
			return &fragmenty[i]
		}
	}
	return nil
}
