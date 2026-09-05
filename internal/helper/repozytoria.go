package helper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	filesmodul "github.com/ultherego/flotestro/internal/modules/files"
	"github.com/ultherego/flotestro/internal/packages"
)

// applyRepository zapisuje albo usuwa zrodlo pakietow.
//
// Kolejnosc jest tu ta sama, co przy certyfikatach i z tego samego powodu:
// wszystko, co da sie sprawdzic bez dotykania dysku, sprawdzamy przed
// pierwszym zapisem, poprzednia tresc trzymamy w pamieci, a jesli metadanych
// nowego zrodla nie da sie pobrac - wracamy do stanu sprzed zmiany. Zrodlo,
// ktore nie odpowiada, zablokowaloby kazda nastepna operacje pakietowa na
// tym hoscie.
func (s *Server) applyRepository(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.RepositoryRequest) *helperv1.HelperResponse {
	timeout := time.Duration(request.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 || timeout > 30*time.Minute {
		timeout = 10 * time.Minute
	}
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	menedzer, err := packages.Detect()
	if err != nil {
		return reject(ErrorUnsupported, err.Error())
	}
	nazwaMenedzera := menedzer.Name()

	repo := packages.Repozytorium{
		ID: action.GetId(), Name: action.GetName(), URL: action.GetUrl(),
		Suites: action.GetSuites(), Components: action.GetComponents(),
		Architectures: action.GetArchitectures(), Enabled: action.GetEnabled(),
		Priority: int(action.GetPriority()), Signed: !action.GetAllowUnsigned(),
		Username: action.GetUsername(), SecretName: action.GetSecretName(),
	}
	if action.GetRemove() {
		repo.URL = ""
	}
	if err := packages.WalidujRepozytorium(repo, nazwaMenedzera,
		len(action.GetPassword()) > 0); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	// Blokady nie obchodzimy: zapis zrodla konczy sie odswiezeniem metadanych,
	// a dwie operacje na tej samej bazie pakietow moga ja uszkodzic.
	if zajeta, sciezka := menedzer.LockHeld(); zajeta {
		return reject(packages.ErrorLocked, "menedzer pakietow jest zajety: "+sciezka)
	}

	// Klucz sprawdzamy przed zapisem: to on rozstrzyga, czyje pakiety host
	// zainstaluje. Odcisk wraca w wyniku, zeby czlowiek mial co porownac
	// z odciskiem podanym przez dostawce.
	odcisk := ""
	if !action.GetRemove() && repo.Signed {
		odcisk, err = packages.OdciskKlucza(action.GetGpgKey())
		if err != nil {
			return reject(ErrorMalformed, err.Error())
		}
		repo.GPGKeyFingerprint = odcisk
	}

	sciezki := packages.SciezkiZrodla(repo.ID, nazwaMenedzera)
	kopie := make([]kopiaPliku, 0, len(sciezki))
	for _, sciezka := range sciezki {
		kopia, err := zapamietajPlik(sciezka)
		if err != nil {
			return reject(ErrorExecFailed, "nie odczytano poprzedniego stanu: "+err.Error())
		}
		kopie = append(kopie, kopia)
	}
	cofnij := func() bool {
		udane := true
		for _, kopia := range kopie {
			if err := kopia.przywroc(); err != nil {
				udane = false
			}
		}
		return udane
	}

	if action.GetRemove() {
		for _, sciezka := range sciezki {
			if err := os.Remove(sciezka); err != nil && !errors.Is(err, os.ErrNotExist) {
				cofnij()
				return reject(ErrorExecFailed, "nie usunieto "+sciezka+": "+err.Error())
			}
		}
		return odpowiedzZrodel(s, nazwaMenedzera, "zrodlo "+repo.ID+" usuniete", "", false)
	}

	pliki, err := packages.PlikiZrodla(repo, nazwaMenedzera, action.GetGpgKey(), action.GetPassword())
	if err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	var sciezkaZrodla string
	for _, plik := range pliki {
		if err := os.MkdirAll(filepath.Dir(plik.Path), 0o755); err != nil {
			cofnij()
			return reject(ErrorExecFailed, err.Error())
		}
		if err := filesmodul.ZapiszAtomowo(plik.Path, plik.Content, plik.Mode, -1, -1); err != nil {
			cofnij()
			// Komunikat niesie sciezke, nigdy tresc: w jednym z tych plikow
			// jest haslo.
			return reject(ErrorExecFailed, "nie zapisano "+plik.Path+": "+err.Error())
		}
		if filepath.Dir(plik.Path) == packages.KatalogZrodelAPT ||
			filepath.Dir(plik.Path) == packages.KatalogZrodelDNF {
			sciezkaZrodla = plik.Path
		}
	}

	// Zapis nie znaczy skutek: pytamy menedzera, czy z tego zrodla da sie
	// cokolwiek pobrac. Zrodlo wylaczone pomijamy - nie ma czego pobierac.
	komunikat := "zrodlo " + repo.ID + " zapisane"
	if repo.Enabled {
		if err := packages.OdswiezZrodlo(actionCtx, nazwaMenedzera, repo.ID, sciezkaZrodla); err != nil {
			cofniete := cofnij()
			powod := "metadanych zrodla nie udalo sie pobrac: " + err.Error()
			if cofniete {
				powod += "; przywrocono poprzedni stan"
			} else {
				powod += "; NIE udalo sie przywrocic poprzedniego stanu"
			}
			return &helperv1.HelperResponse{
				Accepted:  false,
				ErrorCode: ErrorPreconditionFailed,
				Message:   powod,
				RepositoryResult: &helperv1.RepositoryResult{
					Message: powod, GpgKeyFingerprint: odcisk, RolledBack: cofniete,
				},
			}
		}
		komunikat += "; metadane pobrane"
	} else {
		komunikat += "; zrodlo jest wylaczone, wiec metadanych nie pobierano"
	}
	return odpowiedzZrodel(s, nazwaMenedzera, komunikat, odcisk, false)
}

// odpowiedzZrodel sklada wynik razem z obrazem zrodel po zmianie.
func odpowiedzZrodel(s *Server, menedzer, komunikat, odcisk string, cofniete bool) *helperv1.HelperResponse {
	obraz := packages.CzytajRepozytoria(menedzer)
	zakodowany, err := json.Marshal(obraz)
	if err != nil {
		return reject(ErrorExecFailed, err.Error())
	}
	return &helperv1.HelperResponse{
		Accepted: true,
		RepositoryResult: &helperv1.RepositoryResult{
			Snapshot: zakodowany, Message: komunikat,
			GpgKeyFingerprint: odcisk, RolledBack: cofniete,
		},
	}
}

// kopiaPliku trzyma poprzednia zawartosc pliku na czas operacji.
//
// W pamieci, a nie obok pliku: jeden z tych plikow niesie haslo, a kopia
// obok zostawalaby na dysku takze po udanej zmianie.
type kopiaPliku struct {
	sciezka  string
	istnial  bool
	tresc    []byte
	tryb     os.FileMode
	uid, gid int
}

func zapamietajPlik(sciezka string) (kopiaPliku, error) {
	kopia := kopiaPliku{sciezka: sciezka, tryb: 0o644, uid: -1, gid: -1}
	dane, err := os.ReadFile(sciezka)
	if errors.Is(err, os.ErrNotExist) {
		return kopia, nil
	}
	if err != nil {
		return kopia, err
	}
	info, err := os.Stat(sciezka)
	if err != nil {
		return kopia, err
	}
	kopia.istnial = true
	kopia.tresc = dane
	kopia.tryb = info.Mode().Perm()
	return kopia, nil
}

// przywroc wraca do zapamietanej zawartosci pliku.
func (k kopiaPliku) przywroc() error {
	if !k.istnial {
		if err := os.Remove(k.sciezka); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return filesmodul.ZapiszAtomowo(k.sciezka, k.tresc, k.tryb, k.uid, k.gid)
}
