package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/files"

	"golang.org/x/sys/unix"
)

// PlikRejestruPlikow trzyma sciezki, ktore panel zapisal na tym hoscie.
//
// Rejestr jest lokalny, bo to host ma umiec odpowiedziec, jak wygladaja teraz
// pliki, ktorymi panel zarzadza - takze wtedy, gdy panel akurat go nie pyta.
// Bez tego drift bylby widoczny dopiero przy nastepnej operacji.
const PlikRejestruPlikow = "/var/lib/flotestro-helper/pliki.json"

// applyFile obsluguje operacje na plikach konfiguracyjnych.
func (s *Server) applyFile(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 5 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	allowlista := files.WczytajAllowliste(files.SciezkaAllowlisty)

	switch action.GetOperation() {
	case helperv1.FileRequest_OPERATION_LIST:
		return odpowiedzPlikow(s.stanPlikow(), "", nil, "")
	case helperv1.FileRequest_OPERATION_READ:
		return s.czytajPlik(allowlista, action)
	case helperv1.FileRequest_OPERATION_ENSURE:
		return s.zapiszPlik(actionCtx, allowlista, action)
	case helperv1.FileRequest_OPERATION_REMOVE:
		return s.usunPlik(allowlista, action)
	}
	return reject(ErrorUnknownAction, "nieznana operacja na pliku")
}

// czytajPlik zwraca tresc pliku z zakresu.
func (s *Server) czytajPlik(allowlista files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	if odpowiedz := sprawdzZakres(allowlista, action.GetPath()); odpowiedz != nil {
		return odpowiedz
	}
	opis := files.OpiszPlik(action.GetPath())
	if !opis.Exists {
		return reject(ErrorUnsupported, "plik "+action.GetPath()+" nie istnieje na tym hoscie")
	}
	if opis.UnavailableReason != "" {
		return reject(ErrorUnsupported, opis.UnavailableReason)
	}

	plik, err := files.OtworzBezDowiazan(action.GetPath(), unix.O_RDONLY, 0)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	defer plik.Close()

	// Czytamy o bajt wiecej niz granica: inaczej plik dokladnie na granicy
	// wygladalby na urwany, a wiekszy - na caly.
	tresc, err := io.ReadAll(io.LimitReader(plik, files.MaksymalnyRozmiar+1))
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	urwane := false
	if len(tresc) > files.MaksymalnyRozmiar {
		tresc = tresc[:files.MaksymalnyRozmiar]
		urwane = true
	}

	odpowiedz := odpowiedzPlikow(s.stanPlikow(), "", tresc, files.Odcisk(tresc))
	odpowiedz.FileResult.Truncated = urwane
	return odpowiedz
}

// zapiszPlik zapisuje tresc pliku.
//
// Kolejnosc jest cala trescia operacji: sprawdzamy zakres, potem stan hosta
// wobec tego, co operator ogladal, potem sprawdzamy tresc walidatorem - i
// dopiero wtedy piszemy, atomowo. Zapis przed sprawdzeniem zostawialby na
// hoscie plik, ktorego zadna usluga nie wczyta.
func (s *Server) zapiszPlik(ctx context.Context, allowlista files.Allowlist,
	action *helperv1.FileRequest) *helperv1.HelperResponse {
	sciezka := action.GetPath()
	if odpowiedz := sprawdzZakres(allowlista, sciezka); odpowiedz != nil {
		return odpowiedz
	}
	if err := files.WalidujTresc(string(action.GetContent())); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	tryb, err := files.WalidujTryb(action.GetMode())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	uid, gid, err := files.Wlasciciel(action.GetOwner(), action.GetGroup())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	obecny := files.OpiszPlik(sciezka)
	if obecny.UnavailableReason != "" {
		return reject(ErrorUnsupported, obecny.UnavailableReason)
	}
	// Zmiana wykonana po tym, jak operator obejrzal plik, nie moze zniknac
	// pod zapisem z panelu.
	if oczekiwany := action.GetExpectedSha256(); oczekiwany != "" {
		biezacy, err := odciskPliku(sciezka)
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		if biezacy != oczekiwany {
			return reject(ErrorPreconditionFailed,
				"plik zmienil sie od czasu planu (odcisk "+skrot(biezacy)+
					" zamiast "+skrot(oczekiwany)+")")
		}
	} else if obecny.Exists {
		return reject(ErrorPreconditionFailed,
			"plik juz istnieje; zapis wymaga odcisku tresci, ktora zostala obejrzana")
	}

	walidator, maWalidator, err := files.WybierzWalidator(sciezka, action.GetValidator())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	wyjscieWalidatora := ""
	if maWalidator {
		wyjscieWalidatora, err = s.sprawdzTresc(ctx, walidator, sciezka, action.GetContent())
		if err != nil {
			return reject(ErrorMalformed, "walidator "+walidator.Nazwa+": "+err.Error()+
				" "+wyjscieWalidatora)
		}
	}

	if err := files.ZapiszAtomowo(sciezka, action.GetContent(), tryb, uid, gid); err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	s.zapamietajPlik(sciezka, action.GetFromSecret())

	komunikat := "plik zapisany"
	if !maWalidator {
		// Brak sprawdzenia jest faktem, a nie cisza: operator ma wiedziec,
		// ze host przyjal tresc bez sprawdzenia jej znaczenia.
		komunikat += "; panel nie zna walidatora dla tego pliku, wiec tresc nie zostala sprawdzona"
	}
	return odpowiedzPlikow(s.stanPlikow(), komunikat, nil, files.Odcisk(action.GetContent()))
}

// usunPlik kasuje plik z zakresu.
func (s *Server) usunPlik(allowlista files.Allowlist, action *helperv1.FileRequest) *helperv1.HelperResponse {
	sciezka := action.GetPath()
	if odpowiedz := sprawdzZakres(allowlista, sciezka); odpowiedz != nil {
		return odpowiedz
	}
	if oczekiwany := action.GetExpectedSha256(); oczekiwany != "" {
		biezacy, err := odciskPliku(sciezka)
		if err != nil {
			return reject(ErrorExecFailed, err.Error())
		}
		if biezacy != oczekiwany {
			return reject(ErrorPreconditionFailed,
				"plik zmienil sie od czasu planu; usuniecie zabraloby tresc, ktorej nikt nie ogladal")
		}
	}
	if err := os.Remove(sciezka); err != nil && !os.IsNotExist(err) {
		return reject(ErrorExecFailed, err.Error())
	}
	s.zapomnijPlik(sciezka)
	return odpowiedzPlikow(s.stanPlikow(), "plik usuniety", nil, "")
}

// sprawdzTresc uruchamia walidator na tresci zapisanej obok pliku docelowego.
//
// Walidator dostaje plik tymczasowy w tym samym katalogu, bo czesc narzedzi
// czyta sciezki wzgledne wzgledem pliku, ktory sprawdzaja.
func (s *Server) sprawdzTresc(ctx context.Context, walidator files.Walidator,
	sciezka string, tresc []byte) (string, error) {
	if walidator.Wbudowany != nil {
		return "", walidator.Wbudowany(string(tresc))
	}
	if !exists(walidator.Polecenie[0]) {
		// Narzedzia, ktorego host nie ma, nie udajemy: zapis bez sprawdzenia
		// jest wtedy swiadoma decyzja, a nie przeoczeniem.
		return "", nil
	}
	tymczasowy := filepath.Join(filepath.Dir(sciezka), ".flotestro-walidacja-"+filepath.Base(sciezka))
	if err := os.WriteFile(tymczasowy, tresc, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(tymczasowy)

	argumenty := append(append([]string{}, walidator.Polecenie...), tymczasowy)
	wyjscie, err := uruchomNarzedzie(ctx, argumenty)
	return wyjscie, err
}

// stanPlikow opisuje pliki, ktore panel zapisal na tym hoscie.
func (s *Server) stanPlikow() files.Snapshot {
	snapshot := files.Snapshot{ObservedAt: time.Now().UTC()}
	for _, wpis := range s.rejestrPlikow() {
		opis := files.OpiszPlik(wpis.Path)
		opis.Managed = true
		opis.FromSecret = wpis.FromSecret
		switch {
		case !opis.Exists || opis.UnavailableReason != "":
		case wpis.FromSecret:
			// Odcisku tresci z magazynu nie zglaszamy nigdzie: dla krotkiej
			// wartosci sam odcisk jest wskazowka, a magazyn ma nie zostawiac
			// wskazowek poza soba. Panel wie, ktora wersje sekretu wdrozono,
			// i tyle ma wiedziec.
			opis.UnavailableReason = "tresc pochodzi z magazynu sekretow; odcisk nie jest zglaszany"
		default:
			if odcisk, err := odciskPliku(wpis.Path); err == nil {
				opis.SHA256 = odcisk
			} else {
				opis.UnavailableReason = err.Error()
			}
		}
		snapshot.Files = append(snapshot.Files, opis)
	}
	return snapshot
}

// wpisRejestru opisuje jeden plik zapisany przez panel.
type wpisRejestru struct {
	Path string `json:"path"`
	// FromSecret oznacza plik, ktorego tresc przyszla z magazynu sekretow.
	FromSecret bool `json:"from_secret,omitempty"`
}

func (s *Server) rejestrPlikow() []wpisRejestru {
	dane, err := os.ReadFile(PlikRejestruPlikow)
	if err != nil {
		return nil
	}
	var wpisy []wpisRejestru
	if err := json.Unmarshal(dane, &wpisy); err == nil {
		return wpisy
	}
	// Rejestr sprzed wprowadzenia sekretow byl sama lista sciezek. Starszy
	// format czytamy dalej: helper po aktualizacji nie moze zapomniec, ktore
	// pliki panel zapisal.
	var sciezki []string
	if err := json.Unmarshal(dane, &sciezki); err != nil {
		return nil
	}
	wpisy = make([]wpisRejestru, 0, len(sciezki))
	for _, sciezka := range sciezki {
		wpisy = append(wpisy, wpisRejestru{Path: sciezka})
	}
	return wpisy
}

func (s *Server) zapamietajPlik(sciezka string, zSekretu bool) {
	wpisy := s.rejestrPlikow()
	for i := range wpisy {
		if wpisy[i].Path == sciezka {
			wpisy[i].FromSecret = zSekretu
			s.zapiszRejestrPlikow(wpisy)
			return
		}
	}
	wpisy = append(wpisy, wpisRejestru{Path: sciezka, FromSecret: zSekretu})
	sort.Slice(wpisy, func(i, j int) bool { return wpisy[i].Path < wpisy[j].Path })
	s.zapiszRejestrPlikow(wpisy)
}

func (s *Server) zapomnijPlik(sciezka string) {
	wpisy := s.rejestrPlikow()
	pozostale := make([]wpisRejestru, 0, len(wpisy))
	for _, wpis := range wpisy {
		if wpis.Path != sciezka {
			pozostale = append(pozostale, wpis)
		}
	}
	s.zapiszRejestrPlikow(pozostale)
}

func (s *Server) zapiszRejestrPlikow(wpisy []wpisRejestru) {
	dane, err := json.Marshal(wpisy)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(PlikRejestruPlikow), 0o700)
	tymczasowy := PlikRejestruPlikow + ".nowy"
	if err := os.WriteFile(tymczasowy, dane, 0o600); err != nil {
		return
	}
	_ = os.Rename(tymczasowy, PlikRejestruPlikow)
}

func sprawdzZakres(allowlista files.Allowlist, sciezka string) *helperv1.HelperResponse {
	if err := allowlista.Dopuszcza(sciezka); err != nil {
		if errors.Is(err, files.ErrZakazana) {
			return reject(ErrorUnsupported, err.Error())
		}
		return reject(ErrorUnsupported, err.Error()+
			"; zakres wyznacza administrator hosta w "+files.SciezkaAllowlisty)
	}
	return nil
}

func odciskPliku(sciezka string) (string, error) {
	plik, err := files.OtworzBezDowiazan(sciezka, unix.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer plik.Close()
	dane, err := io.ReadAll(io.LimitReader(plik, files.MaksymalnyRozmiar))
	if err != nil {
		return "", err
	}
	return files.Odcisk(dane), nil
}

func skrot(odcisk string) string {
	if len(odcisk) > 12 {
		return odcisk[:12]
	}
	return odcisk
}

func odpowiedzPlikow(snapshot files.Snapshot, komunikat string,
	tresc []byte, odcisk string) *helperv1.HelperResponse {
	zakodowane, err := json.Marshal(snapshot)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		FileResult: &helperv1.FileResult{
			Snapshot: zakodowane, Message: komunikat,
			Content: tresc, Sha256: odcisk,
		},
	}
}
