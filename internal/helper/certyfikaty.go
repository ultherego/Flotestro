package helper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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
func (s *Server) wdrozCertyfikat(ctx context.Context,
	action *helperv1.CertificateRequest) *helperv1.HelperResponse {
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
