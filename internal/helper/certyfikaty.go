package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/certificates"
	"github.com/ultherego/flotestro/internal/modules/files"
)

// PlikRejestruCertyfikatow trzyma cele, o ktore panel prosil na tym hoscie.
//
// Rejestr jest lokalny z tego samego powodu, co przy plikach zarzadzanych:
// to host ma umiec powiedziec, jak wygladaja teraz certyfikaty jego uslug -
// takze wtedy, gdy panel akurat go nie pyta. Bez tego zakladka pokazywalaby
// stan sprzed ostatniego skanu, a wygasajacy certyfikat zauwazylby dopiero
// ten, kto o niego zapyta.
const PlikRejestruCertyfikatow = "/var/lib/flotestro-helper/certyfikaty.json"

// nazwyFaktowCertyfikatow tlumaczy wyliczenie protokolu na nazwy faktow.
//
// Tlumaczenie istnieje po to, zeby helper nie przyjmowal dowolnego napisu:
// zakres jego pracy jest zamknieta lista, a nie tekstem od agenta.
var nazwyFaktowCertyfikatow = map[helperv1.CertificateRequest_Fact]string{
	helperv1.CertificateRequest_FACT_KEY_METADATA:      certificates.FaktMetadaneKluczy,
	helperv1.CertificateRequest_FACT_RENEWAL_TRACKING:  certificates.FaktSledzenie,
	helperv1.CertificateRequest_FACT_CERTIFICATE_FILES: certificates.FaktTrescPliku,
}

// applyCertificate obsluguje operacje modulu certyfikatow.
func (s *Server) applyCertificate(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action.GetOperation() {
	case helperv1.CertificateRequest_OPERATION_FACTS:
		return s.faktyCertyfikatow(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_PLAN:
		// Plan bez materialu jest planem odnowienia: wdrozenie zawsze niesie
		// certyfikat, odnowienie nigdy - po nowy idzie demon hosta.
		if len(action.GetCertificate()) == 0 {
			return s.zaplanujOdnowienie(actionCtx, action)
		}
		return s.zaplanujCertyfikat(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_TRUST_PLAN:
		return s.zaplanujZaufanie(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_TRUST_ENSURE,
		helperv1.CertificateRequest_OPERATION_TRUST_REMOVE:
		return s.zmienZaufanie(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_DEPLOY:
		return s.wdrozCertyfikat(actionCtx, action)
	case helperv1.CertificateRequest_OPERATION_RENEW:
		return s.odnowCertyfikat(actionCtx, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja modulu certyfikatow")
}

// celeZadania czyta cele ze zlecenia i sprawdza kazda sciezke wlasna regula.
func celeZadania(action *helperv1.CertificateRequest) ([]certificates.Cel, *helperv1.HelperResponse) {
	cele := make([]certificates.Cel, 0, len(action.GetTargets()))
	for _, cel := range action.GetTargets() {
		if err := certificates.WalidujSciezke(cel.GetPath()); err != nil {
			return nil, reject(ErrorMalformed, err.Error())
		}
		if cel.GetKeyPath() != "" {
			if err := certificates.WalidujSciezke(cel.GetKeyPath()); err != nil {
				return nil, reject(ErrorMalformed, err.Error())
			}
		}
		cele = append(cele, certificates.Cel{
			Path: cel.GetPath(), KeyPath: cel.GetKeyPath(), Service: cel.GetService(),
		})
	}
	return cele, nil
}

// faktyCertyfikatow odczytuje wylacznie te fakty, o ktore agent poprosil.
func (s *Server) faktyCertyfikatow(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	zadane := action.GetFacts()
	if len(zadane) == 0 {
		return reject(ErrorMalformed, "zlecenie nie wskazuje zadnego faktu")
	}
	nazwy := make([]string, 0, len(zadane))
	for _, fakt := range zadane {
		nazwa, znany := nazwyFaktowCertyfikatow[fakt]
		if !znany {
			return reject(ErrorMalformed, "nieznany fakt "+fakt.String())
		}
		nazwy = append(nazwy, nazwa)
	}

	cele, odmowa := celeZadania(action)
	if odmowa != nil {
		return odmowa
	}
	// Lista panelu zastepuje rejestr tylko wtedy, gdy panel mowi, ze jest
	// pelna. Zwykly odczyt inwentarza nie kasuje niczego: agent pyta wtedy
	// o fakty bez celow i dostaje to, co host juz zna.
	if action.GetAuthoritative() {
		s.zapiszRejestrCertyfikatow(cele)
	}
	znane := polaczCele(s.rejestrCertyfikatow(), cele)
	// Rejestr pamieta cele wdrozen, a pliki z nich bywaja kasowane poza
	// panelem. Cel bez pliku nie jest wiedza - jest smieciem, ktory zajmuje
	// miejsce w odczycie i wypycha z niego certyfikaty, ktore host naprawde
	// ma. Zapominamy go dopiero, gdy pliku nie ma: plik nieczytelny to inna
	// odpowiedz niz plik nieistniejacy.
	if zyjace := celeZIstniejacymPlikiem(znane); len(zyjace) != len(znane) {
		znane = zyjace
		s.zapiszRejestrCertyfikatow(zyjace)
	}

	dodatki := certificates.ZbierzUzupelnienie(ctx, wyjscieNarzedzia, nazwy, znane)
	dodatki.Targets = znane
	zakodowane, err := json.Marshal(dodatki)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted:          true,
		CertificateResult: &helperv1.CertificateResult{Facts: zakodowane},
	}
}

// wdrozCertyfikat podmienia certyfikat i klucz, po czym sprawdza skutek.
//
// Kolejnosc jest tu cala trescia: wszystko, co da sie sprawdzic bez dotykania
// dysku, sprawdzamy przed pierwszym zapisem; poprzednia zawartosc trzymamy
// w pamieci; a jesli usluga po przeladowaniu nie pokazuje nowego certyfikatu,
// wracamy do poprzedniego i mowimy o tym wprost. Wdrozenie, ktore zostawia
// usluge martwa, nie jest wdrozeniem.
// zaplanujCertyfikat liczy roznice miedzy certyfikatem, ktory host ma pod
// sciezka, a tym z zamowienia. Nie dotyka plikow i nie siega po klucz
// prywatny: plan trafia do bazy panelu, wiec nie moze niesc materialu.
func (s *Server) zaplanujCertyfikat(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	plan := s.planCertyfikatu(action)
	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "wdrozenie nie wejdzie na ten host: " + plan.Refusal
	switch {
	case plan.Refusal != "":
	case plan.Action == certificates.PlanBezZmian:
		komunikat = "host ma juz ten certyfikat pod " + plan.Path
	default:
		komunikat = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: komunikat, Plan: zakodowany,
			FingerprintSha256: plan.DesiredFingerprint,
		},
	}
}

// planCertyfikatu sklada plan wdrozenia wobec pliku, ktory host ma teraz.
func (s *Server) planCertyfikatu(action *helperv1.CertificateRequest) certificates.Plan {
	obecny := certificates.Certyfikat{}
	if err := certificates.WalidujSciezke(action.GetPath()); err == nil {
		migawka := certificates.Skanuj([]certificates.Cel{{
			Path: action.GetPath(), KeyPath: action.GetKeyPath(),
			Service: action.GetReloadUnit(),
		}})
		if len(migawka.Certificates) > 0 {
			obecny = migawka.Certificates[0]
		}
	}
	return certificates.Zaplanuj(obecny, certificates.Zamowienie{
		Path:       action.GetPath(),
		KeyPath:    action.GetKeyPath(),
		Certyfikat: string(action.GetCertificate()),
		KeySecret:  action.GetKeySecretRef(),
		Jednostka:  action.GetReloadUnit(),
		Cel:        action.GetProbeTarget(),
		MaKlucz:    action.GetKeySecretRef() != "" || len(action.GetKey()) > 0,
	}, time.Now())
}

func (s *Server) wdrozCertyfikat(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	// Wdrozenie zatwierdzone na podstawie planu ma wejsc w ten stan, ktory
	// operator ogladal: inny certyfikat pod ta sciezka od planowania jest
	// odmowa, a nie ostrzezeniem.
	if oczekiwany := action.GetPlanHash(); oczekiwany != "" {
		if teraz := s.planCertyfikatu(action); teraz.PlanHash != oczekiwany {
			return reject(ErrorPreconditionFailed,
				"certyfikat pod "+action.GetPath()+" zmienil sie od planowania; wdrozenie wymaga nowego planu")
		}
	}
	wdrozenie := certificates.Wdrozenie{
		Path:       action.GetPath(),
		KeyPath:    action.GetKeyPath(),
		Certyfikat: action.GetCertificate(),
		Klucz:      action.GetKey(),
		Owner:      action.GetOwner(),
		Group:      action.GetGroup(),
		Mode:       action.GetMode(),
		KeyMode:    action.GetKeyMode(),
		Jednostka:  action.GetReloadUnit(),
		Cel:        action.GetProbeTarget(),
	}
	certy, err := certificates.Sprawdz(wdrozenie, time.Now())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	odcisk := certificates.Odcisk(certy[0])

	uid, gid, err := files.Wlasciciel(wdrozenie.Owner, wdrozenie.Group)
	if err != nil {
		return reject(ErrorPreconditionFailed, err.Error())
	}

	kopiaCertyfikatu, err := certificates.Zapamietaj(wdrozenie.Path)
	if err != nil {
		return reject(ErrorExecFailed, "nie odczytano poprzedniego certyfikatu: "+err.Error())
	}
	kopiaKlucza, err := certificates.Zapamietaj(wdrozenie.KeyPath)
	if err != nil {
		return reject(ErrorExecFailed, "nie odczytano poprzedniego klucza: "+err.Error())
	}
	cofnij := func() bool {
		bladCertyfikatu := kopiaCertyfikatu.Przywroc()
		bladKlucza := kopiaKlucza.Przywroc()
		if wdrozenie.Jednostka != "" {
			_, _ = uruchomNarzedzie(ctx,
				[]string{"/usr/bin/systemctl", "reload-or-restart", wdrozenie.Jednostka})
		}
		return bladCertyfikatu == nil && bladKlucza == nil
	}

	if err := certificates.Zapisz(wdrozenie, uid, gid); err != nil {
		cofnij()
		return reject(ErrorExecFailed, "nie zapisano certyfikatu: "+err.Error())
	}

	komunikat := "certyfikat zapisany"
	if wdrozenie.Jednostka != "" {
		// Przeladowanie, a nie restart, gdy tylko usluga je obsluguje:
		// polaczenia, ktore juz trwaja, maja przezyc wymiane certyfikatu.
		if wyjscie, err := uruchomNarzedzie(ctx,
			[]string{"/usr/bin/systemctl", "reload-or-restart", wdrozenie.Jednostka}); err != nil {
			cofniete := cofnij()
			return odmowaWdrozenia(odcisk, certy[0].NotAfter,
				"przeladowanie "+wdrozenie.Jednostka+" nie powiodlo sie: "+wyjscie, cofniete)
		}
		komunikat += "; " + wdrozenie.Jednostka + " przeladowana"
	}

	var sonda certificates.WynikSondy
	if wdrozenie.Cel != "" {
		sonda = certificates.Sonda(ctx, wdrozenie.Cel)
		if !sonda.Potwierdza(odcisk) {
			powod := sonda.Error
			if powod == "" {
				powod = "usluga podaje inny certyfikat niz wdrozony"
			}
			cofniete := cofnij()
			odpowiedz := odmowaWdrozenia(odcisk, certy[0].NotAfter,
				"sonda "+wdrozenie.Cel+": "+powod, cofniete)
			odpowiedz.CertificateResult.Probe = zakodujSonde(sonda)
			return odpowiedz
		}
		komunikat += "; usluga pokazuje nowy certyfikat"
	}

	s.zapamietajCertyfikat(certificates.Cel{
		Path: wdrozenie.Path, KeyPath: wdrozenie.KeyPath, Service: wdrozenie.Jednostka,
	})
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message:           komunikat,
			FingerprintSha256: odcisk,
			NotAfter:          certy[0].NotAfter.UTC().Format(time.RFC3339),
			Probe:             zakodujSonde(sonda),
		},
	}
}

// odnowCertyfikat prosi certmongera o nowy certyfikat na to samo zlecenie.
//
// Panel nie podaje tu tresci: odnowienie robi demon hosta, ktory ma wlasny
// klucz i wlasne uzgodnienie z urzedem. Zadaniem panelu jest poprosic
// i sprawdzic, czy cos z tego wyszlo.
func (s *Server) odnowCertyfikat(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	narzedzie := certificates.SciezkaNarzedzia()
	if narzedzie == "" {
		return reject(ErrorUnsupported, "ten host nie ma certmongera")
	}
	// Odnowienie zatwierdzone na podstawie planu ma dotyczyc tego zlecenia,
	// ktore operator ogladal: inne zlecenie pod ta sciezka od planowania
	// jest odmowa, a nie cichym odnowieniem czegos innego.
	if oczekiwany := action.GetPlanHash(); oczekiwany != "" {
		if teraz := s.planOdnowienia(ctx, action); teraz.PlanHash != oczekiwany {
			return reject(ErrorPreconditionFailed,
				"zlecenie certmongera pod "+action.GetPath()+
					" zmienilo sie od planowania; odnowienie wymaga nowego planu")
		}
	}

	// Zlecenie wskazuje panel identyfikatorem albo sciezka pliku. Identyfikator
	// jest inny na kazdym hoscie, wiec kampania odnawiajaca ten sam certyfikat
	// na calej flocie moze podac tylko sciezke - a host odnajduje zlecenie sam.
	zlecenie := action.GetRequest()
	if zlecenie == "" {
		sciezka := action.GetPath()
		if err := certificates.WalidujSciezke(sciezka); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		wyjscie, err := wyjscieNarzedzia(ctx, narzedzie, "list")
		if err != nil {
			return reject(ErrorExecFailed, "getcert list: "+err.Error()+" "+wyjscie)
		}
		sledzenie, pilnowany := certificates.ParsujGetcert(wyjscie)[sciezka]
		if !pilnowany || sledzenie.Request == "" {
			return reject(ErrorPreconditionFailed,
				"certmonger nie pilnuje pliku "+sciezka+", wiec nie ma czego odnowic")
		}
		zlecenie = sledzenie.Request
	}
	if err := certificates.WalidujZlecenie(zlecenie); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	if wyjscie, err := wyjscieNarzedzia(ctx, narzedzie,
		"resubmit", "-i", zlecenie, "-w"); err != nil {
		return reject(ErrorExecFailed, "getcert resubmit: "+err.Error()+" "+wyjscie)
	}

	// Zlecenie wyslane to nie certyfikat odnowiony: pytamy demona, w jakim
	// stanie jest teraz i co lezy na dysku.
	stan := certificates.Sledzenie{}
	if wyjscie, err := wyjscieNarzedzia(ctx, narzedzie, "list", "-i", zlecenie); err == nil {
		for _, sledzenie := range certificates.ParsujGetcert(wyjscie) {
			stan = sledzenie
			break
		}
	}
	komunikat := "odnowienie zlecone"
	if stan.Status != "" {
		komunikat += "; certmonger zglasza " + stan.Status
	}

	wynik := &helperv1.CertificateResult{Message: komunikat}
	if stan.Expires != nil {
		wynik.NotAfter = stan.Expires.UTC().Format(time.RFC3339)
	}

	if jednostka := action.GetReloadUnit(); jednostka != "" {
		if err := certificates.WalidujJednostke(jednostka); err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if wyjscie, err := uruchomNarzedzie(ctx,
			[]string{"/usr/bin/systemctl", "reload-or-restart", jednostka}); err != nil {
			return reject(ErrorExecFailed, "przeladowanie "+jednostka+": "+wyjscie)
		}
		wynik.Message += "; " + jednostka + " przeladowana"
	}
	if cel := action.GetProbeTarget(); cel != "" {
		sonda := certificates.Sonda(ctx, cel)
		wynik.Probe = zakodujSonde(sonda)
		wynik.FingerprintSha256 = sonda.FingerprintSHA256
		if !sonda.Reachable {
			wynik.Message += "; sonda " + cel + " nie odpowiada"
		}
	}
	return &helperv1.HelperResponse{Accepted: true, CertificateResult: wynik}
}

// odmowaWdrozenia sklada odpowiedz o nieudanym wdrozeniu wraz z tym, czy
// host wrocil do poprzedniego stanu.
func odmowaWdrozenia(odcisk string, termin time.Time, powod string, cofniete bool) *helperv1.HelperResponse {
	komunikat := powod
	if cofniete {
		komunikat += "; przywrocono poprzedni certyfikat"
	} else {
		// Nieudany powrot jest gorsza wiadomoscia niz nieudane wdrozenie
		// i nie moze zginac w tym samym zdaniu.
		komunikat += "; NIE udalo sie przywrocic poprzedniego certyfikatu"
	}
	return &helperv1.HelperResponse{
		Accepted:  false,
		ErrorCode: ErrorPreconditionFailed,
		Message:   komunikat,
		CertificateResult: &helperv1.CertificateResult{
			Message:           komunikat,
			FingerprintSha256: odcisk,
			NotAfter:          termin.UTC().Format(time.RFC3339),
			RolledBack:        cofniete,
		},
	}
}

func zakodujSonde(sonda certificates.WynikSondy) []byte {
	if sonda.Target == "" {
		return nil
	}
	dane, err := json.Marshal(sonda)
	if err != nil {
		return nil
	}
	return dane
}

// polaczCele scala liste rejestru z lista ze zlecenia, bez powtorzen.
func polaczCele(rejestr, cele []certificates.Cel) []certificates.Cel {
	wynik := make([]certificates.Cel, 0, len(rejestr)+len(cele))
	pozycje := map[string]int{}
	dodaj := func(cel certificates.Cel) {
		if i, znany := pozycje[cel.Path]; znany {
			// Nowsza wiedza wygrywa: panel moze dopisac klucz albo usluge
			// do celu, ktory host znal wczesniej z samej sciezki.
			if cel.KeyPath != "" {
				wynik[i].KeyPath = cel.KeyPath
			}
			if cel.Service != "" {
				wynik[i].Service = cel.Service
			}
			return
		}
		pozycje[cel.Path] = len(wynik)
		wynik = append(wynik, cel)
	}
	for _, cel := range rejestr {
		dodaj(cel)
	}
	for _, cel := range cele {
		dodaj(cel)
	}
	sort.Slice(wynik, func(i, j int) bool { return wynik[i].Path < wynik[j].Path })
	return wynik
}

func (s *Server) rejestrCertyfikatow() []certificates.Cel {
	dane, err := os.ReadFile(PlikRejestruCertyfikatow)
	if err != nil {
		return nil
	}
	var cele []certificates.Cel
	if err := json.Unmarshal(dane, &cele); err != nil {
		return nil
	}
	return cele
}

func (s *Server) zapamietajCertyfikat(cel certificates.Cel) {
	s.zapiszRejestrCertyfikatow(polaczCele(s.rejestrCertyfikatow(), []certificates.Cel{cel}))
}

func (s *Server) zapiszRejestrCertyfikatow(cele []certificates.Cel) {
	dane, err := json.Marshal(cele)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(PlikRejestruCertyfikatow), 0o700)
	tymczasowy := PlikRejestruCertyfikatow + ".nowy"
	if err := os.WriteFile(tymczasowy, dane, 0o600); err != nil {
		return
	}
	_ = os.Rename(tymczasowy, PlikRejestruCertyfikatow)
}

// magazynZaufania czyta kotwice, ktore host ma teraz.
func (s *Server) magazynZaufania() certificates.MagazynZaufania {
	return certificates.CzytajKotwice(certificates.WykryjMagazyn(exists))
}

// planZaufania sklada plan kroku rotacji wobec stanu magazynu.
//
// Usuniecie patrzy takze na certyfikaty hosta: urzad, ktory nadal cos
// podpisuje, nie moze zniknac z magazynu, bo zerwaloby to zaufanie
// klientom, ktorzy niczego nie zmieniali.
func (s *Server) planZaufania(ctx context.Context, action *helperv1.CertificateRequest,
	magazyn certificates.MagazynZaufania) certificates.PlanZaufania {
	// Plan bez materialu jest planem wycofania: zaufanie zawsze niesie
	// zaswiadczenie urzedu, wycofanie nigdy. Operacja planujaca jest jedna
	// dla obu krokow rotacji, wiec rodzaj poznaje sie po polach.
	usuwanie := action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_REMOVE ||
		(action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_PLAN &&
			len(action.GetCertificate()) == 0)
	if usuwanie {
		return certificates.ZaplanujUsuniecieKotwicy(magazyn, action.GetAnchorId(),
			s.certyfikatyHosta(ctx))
	}
	return certificates.ZaplanujKotwice(magazyn, action.GetAnchorId(),
		string(action.GetCertificate()), time.Now())
}

// certyfikatyHosta czyta certyfikaty, ktore host ma pod obserwacja panelu.
func (s *Server) certyfikatyHosta(ctx context.Context) []certificates.Certyfikat {
	cele := s.rejestrCertyfikatow()
	if len(cele) == 0 {
		return nil
	}
	migawka := certificates.Skanuj(cele)
	migawka = migawka.Uzupelnij(certificates.ZbierzUzupelnienie(ctx, wyjscieNarzedzia,
		migawka.Brakujace(), cele))
	return migawka.Certificates
}

// zaplanujZaufanie liczy krok rotacji bez dotykania magazynu.
func (s *Server) zaplanujZaufanie(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	magazyn := s.magazynZaufania()
	plan := s.planZaufania(ctx, action, magazyn)
	return odpowiedzZaufania(magazyn, plan, opisPlanuZaufania(plan), nil)
}

// zmienZaufanie zaklada albo wycofuje kotwice panelu i przelicza magazyn.
//
// Kolejnosc jest tu cala trescia: plik wchodzi do katalogu kotwic, narzedzie
// przelicza wiazke, a dopiero gotowa wiazka jest odpowiedzia. Sam plik bez
// przeliczenia nie zmienia niczego - i wygladalby jak zmiana, ktorej nie ma.
func (s *Server) zmienZaufanie(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	magazyn := s.magazynZaufania()
	if magazyn.UnavailableReason != "" {
		return reject(ErrorUnsupported, magazyn.UnavailableReason)
	}
	plan := s.planZaufania(ctx, action, magazyn)
	if plan.Refusal != "" {
		return reject(ErrorPreconditionFailed, plan.Refusal)
	}
	// Zmiana zatwierdzona na podstawie planu ma wejsc w ten stan, ktory
	// operator ogladal: inna kotwica pod ta nazwa od planowania jest odmowa.
	if oczekiwany := action.GetPlanHash(); oczekiwany != "" && plan.PlanHash != oczekiwany {
		return reject(ErrorPreconditionFailed,
			"magazyn zaufania zmienil sie od planowania; krok wymaga nowego planu")
	}

	usuwanie := action.GetOperation() == helperv1.CertificateRequest_OPERATION_TRUST_REMOVE
	sciezka := certificates.SciezkaKotwicy(magazyn, action.GetAnchorId())
	if sciezka == "" {
		return reject(ErrorMalformed, "nie da sie zlozyc sciezki kotwicy")
	}
	poprzednia, err := certificates.Zapamietaj(sciezka)
	if err != nil {
		return reject(ErrorExecFailed, "nie odczytano poprzedniej kotwicy: "+err.Error())
	}

	switch {
	case usuwanie:
		if plan.Action == certificates.PlanJuzUsuniety {
			return odpowiedzZaufania(s.magazynZaufania(), plan,
				"host nie ufal temu urzedowi, wiec nie ma czego wycofywac", nil)
		}
		if err := os.Remove(sciezka); err != nil && !os.IsNotExist(err) {
			return reject(ErrorExecFailed, "usuniecie kotwicy: "+err.Error())
		}
	default:
		if plan.Action == certificates.PlanBezZmian {
			return odpowiedzZaufania(magazyn, plan,
				"host juz ufa temu urzedowi", nil)
		}
		material, _, err := certificates.SkladajKotwice(string(action.GetCertificate()), time.Now())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		if err := zapiszPlikJadra(sciezka, string(material), 0o644); err != nil {
			return reject(ErrorExecFailed, "zapis kotwicy: "+err.Error())
		}
	}

	if wyjscie, err := uruchomNarzedzie(ctx, poleceniePrzeliczenia(magazyn)); err != nil {
		// Magazyn, ktorego nie da sie przeliczyc, zostawilby host z wiazka
		// sprzed zmiany i kotwica, ktorej nikt nie widzial. Wracamy do
		// poprzedniego pliku i probujemy przeliczyc jeszcze raz.
		_ = poprzednia.Przywroc()
		_, _ = uruchomNarzedzie(ctx, poleceniePrzeliczenia(magazyn))
		return reject(ErrorExecFailed, "przeliczenie magazynu zaufania: "+err.Error()+": "+wyjscie)
	}

	komunikat := "host ufa urzedowi " + plan.DesiredSubject
	if usuwanie {
		komunikat = "host przestal ufac urzedowi " + plan.AnchorID
	}
	return odpowiedzZaufania(s.magazynZaufania(), plan, komunikat, nil)
}

// poleceniePrzeliczenia sklada wywolanie narzedzia magazynu.
func poleceniePrzeliczenia(magazyn certificates.MagazynZaufania) []string {
	if magazyn.Adapter == certificates.AdapterRHEL {
		return []string{magazyn.Tool, "extract"}
	}
	return []string{magazyn.Tool}
}

// opisPlanuZaufania streszcza plan jednym zdaniem dla dziennika operacji.
func opisPlanuZaufania(plan certificates.PlanZaufania) string {
	switch {
	case plan.Refusal != "":
		return "krok nie wejdzie na ten host: " + plan.Refusal
	case plan.Action == certificates.PlanBezZmian:
		return "host juz ufa temu urzedowi"
	case plan.Action == certificates.PlanJuzUsuniety:
		return "host nie ufa temu urzedowi, wiec nie ma czego wycofywac"
	default:
		return strings.Join(plan.Changes, "; ")
	}
}

func odpowiedzZaufania(magazyn certificates.MagazynZaufania, plan certificates.PlanZaufania,
	komunikat string, _ error) *helperv1.HelperResponse {
	zakodowanyPlan, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	zakodowanyMagazyn, err := json.Marshal(magazyn)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: komunikat, Plan: zakodowanyPlan, Trust: zakodowanyMagazyn,
			FingerprintSha256: plan.DesiredFingerprint,
		},
	}
}

// zaplanujOdnowienie liczy plan odnowienia bez proszenia urzedu o cokolwiek.
func (s *Server) zaplanujOdnowienie(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
	plan := s.planOdnowienia(ctx, action)
	zakodowany, err := json.Marshal(plan)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	komunikat := "odnowienie nie wejdzie na ten host: " + plan.Refusal
	if plan.Refusal == "" {
		komunikat = strings.Join(plan.Changes, "; ")
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		CertificateResult: &helperv1.CertificateResult{
			Message: komunikat, Plan: zakodowany,
			FingerprintSha256: plan.CurrentFingerprint,
		},
	}
}

// planOdnowienia sklada plan wobec tego, co host ma i co pilnuje certyfikatu.
func (s *Server) planOdnowienia(ctx context.Context,
	action *helperv1.CertificateRequest) certificates.PlanOdnowienia {
	sciezka := action.GetPath()
	narzedzie := certificates.SciezkaNarzedzia()

	obecny := certificates.Certyfikat{}
	if err := certificates.WalidujSciezke(sciezka); err == nil {
		migawka := certificates.Skanuj([]certificates.Cel{{
			Path: sciezka, KeyPath: action.GetKeyPath(), Service: action.GetReloadUnit(),
		}})
		if len(migawka.Certificates) > 0 {
			obecny = migawka.Certificates[0]
		}
	}

	var sledzenie *certificates.Sledzenie
	if narzedzie != "" {
		if wyjscie, err := wyjscieNarzedzia(ctx, narzedzie, "list"); err == nil {
			if wpis, pilnowany := certificates.ParsujGetcert(wyjscie)[sciezka]; pilnowany {
				kopia := wpis
				sledzenie = &kopia
			}
		}
	}
	return certificates.ZaplanujOdnowienie(obecny, sledzenie, narzedzie != "",
		sciezka, action.GetReloadUnit(), time.Now())
}

// celeZIstniejacymPlikiem odsiewa cele, ktorych pliku juz nie ma.
//
// Brak pliku rozstrzygamy bledem ENOENT, a nie kazdym bledem odczytu: plik
// w katalogu zamknietym dla helpera nadal istnieje i nadal jest celem.
func celeZIstniejacymPlikiem(cele []certificates.Cel) []certificates.Cel {
	zyjace := make([]certificates.Cel, 0, len(cele))
	for _, cel := range cele {
		if _, err := os.Lstat(cel.Path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		zyjace = append(zyjace, cel)
	}
	return zyjace
}
