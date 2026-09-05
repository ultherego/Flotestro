package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Runbook uruchamia skrypt przygotowany przez administratora hosta.
//
// To jest jedyne miejsce w calym systemie, w ktorym panel uruchamia cos, czego
// sam nie zna - i dlatego jest obwarowane trzema regulami. Panel nie przesyla
// tresci skryptu, tylko jego nazwe. Skrypt musi juz lezec w katalogu, do
// ktorego pisze wylacznie root. I musi odpowiadac ustalonym kontraktem, a nie
// dowolnym tekstem: inaczej "runbook" bylby zdalnym wykonaniem dowolnego kodu
// z ladniejsza nazwa.
type Runbook struct{}

func (r *Runbook) Nazwa() string { return NarzedzieRunbook }

// Dostepny mowi, czy host w ogole ma katalog runbookow.
func (r *Runbook) Dostepny() bool {
	info, err := os.Stat(KatalogRunbookow)
	return err == nil && info.IsDir()
}

func (r *Runbook) Wersja(context.Context) string { return "" }

// Sciezka sprawdza skrypt i zwraca jego pelna sciezke.
//
// Sprawdzamy wlasciciela i prawa, a nie tylko istnienie: skrypt zapisywalny
// dla zwyklego uzytkownika oznaczalby, ze kazdy uzytkownik hosta moze
// podstawic panelowi kod do wykonania z prawami roota.
func (r *Runbook) Sciezka(nazwa string) (string, error) {
	if !nazwaRunbooka.MatchString(nazwa) {
		return "", fmt.Errorf("nieprawidlowa nazwa runbooka %q", nazwa)
	}
	sciezka := filepath.Join(KatalogRunbookow, nazwa)
	info, err := os.Lstat(sciezka)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("na tym hoscie nie ma runbooka %q", nazwa)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("runbook %q nie jest zwyklym plikiem", nazwa)
	}
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return "", fmt.Errorf("nie udalo sie odczytac wlasciciela runbooka %q", nazwa)
	}
	if stat.Uid != 0 {
		return "", fmt.Errorf("runbook %q nie nalezy do roota", nazwa)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("runbook %q jest zapisywalny poza rootem", nazwa)
	}
	if info.Mode().Perm()&0o100 == 0 {
		return "", fmt.Errorf("runbook %q nie jest wykonywalny", nazwa)
	}
	return sciezka, nil
}

// srodowisko sklada zmienne opisujace zlecenie.
//
// Wszystko idzie srodowiskiem, a nie argumentami: argumenty widzi kazdy
// uzytkownik hosta przez /proc, a wsrod zmiennych jest haslo repozytorium.
func (r *Runbook) srodowisko(zlecenie Zlecenie, operacja string) []string {
	srodowisko := append(srodowiskoNarzedzia(zlecenie, "FLOTESTRO_BACKUP_PASSWORD"),
		"FLOTESTRO_BACKUP_OPERATION="+operacja,
		"FLOTESTRO_BACKUP_ID="+zlecenie.ID,
		"FLOTESTRO_BACKUP_REPOSITORY="+zlecenie.Repository,
		"FLOTESTRO_BACKUP_PATHS="+strings.Join(zlecenie.Paths, "\n"),
		"FLOTESTRO_BACKUP_EXCLUDES="+strings.Join(zlecenie.Excludes, "\n"),
		"FLOTESTRO_BACKUP_TAGS="+strings.Join(zlecenie.Tags, "\n"),
	)
	if operacja == OperacjaOdtworzen {
		srodowisko = append(srodowisko,
			"FLOTESTRO_BACKUP_SNAPSHOT="+zlecenie.Odtworzenie.SnapshotID,
			"FLOTESTRO_BACKUP_TARGET="+zlecenie.Odtworzenie.Target,
			"FLOTESTRO_BACKUP_INCLUDE="+strings.Join(zlecenie.Odtworzenie.Include, "\n"),
			"FLOTESTRO_BACKUP_OVERWRITE="+zlecenie.Odtworzenie.Overwrite,
		)
	}
	if operacja == OperacjaSprawdz && zlecenie.ReadData {
		srodowisko = append(srodowisko, "FLOTESTRO_BACKUP_READ_DATA=1")
	}
	return srodowisko
}

// wywolaj uruchamia runbook i zwraca ostatnia linie jego wyjscia oraz calosc.
//
// Kontrakt jest waski celowo: runbook moze pisac, co chce, ale ostatnia linia
// musi byc dokumentem JSON. Panel czyta wylacznie ja - reszta jest dziennikiem
// dla czlowieka, a nie danymi.
func (r *Runbook) wywolaj(ctx context.Context, zlecenie Zlecenie,
	operacja string, postep PostepFunc) (string, wynikPolecenia, error) {
	sciezka, err := r.Sciezka(zlecenie.Runbook)
	if err != nil {
		return "", wynikPolecenia{}, err
	}
	var ostatnia string
	uruchomienie := uruchom(ctx, sciezka, []string{operacja},
		r.srodowisko(zlecenie, operacja), tajneZlecenia(zlecenie),
		func(linia string) {
			przycieta := strings.TrimSpace(linia)
			if przycieta == "" {
				return
			}
			if strings.HasPrefix(przycieta, "{") {
				ostatnia = przycieta
				return
			}
			if postep != nil {
				postep(Postep{Message: przycieta})
			}
		})
	if !uruchomienie.Ran || uruchomienie.Err != nil || uruchomienie.ExitCode != 0 {
		return ostatnia, uruchomienie, fmt.Errorf("runbook %s %s: %s",
			zlecenie.Runbook, operacja, uruchomienie.Powod())
	}
	return ostatnia, uruchomienie, nil
}

// odpowiedzRunbooka jest kontraktem wyjscia skryptu.
type odpowiedzRunbooka struct {
	Snapshots []struct {
		ID        string   `json:"id"`
		Time      string   `json:"time"`
		SizeBytes uint64   `json:"size_bytes"`
		Paths     []string `json:"paths"`
	} `json:"snapshots"`
	TotalSizeBytes  uint64  `json:"total_size_bytes"`
	SnapshotID      string  `json:"snapshot_id"`
	BytesAdded      uint64  `json:"bytes_added"`
	FilesNew        uint64  `json:"files_new"`
	FilesRestored   uint64  `json:"files_restored"`
	DurationSeconds float64 `json:"duration_seconds"`
	Message         string  `json:"message"`
}

// Plan pyta runbook o stan repozytorium.
func (r *Runbook) Plan(ctx context.Context, zlecenie Zlecenie) (Stan, error) {
	stan := Stan{Tool: NarzedzieRunbook, Repository: zlecenie.Repository, ObservedAt: time.Now().UTC()}
	linia, uruchomienie, err := r.wywolaj(ctx, zlecenie, OperacjaPlan, nil)
	if err != nil {
		stan.UnavailableReason = uruchomienie.Powod()
		if stan.UnavailableReason == "" {
			stan.UnavailableReason = err.Error()
		}
		return stan, err
	}
	if linia == "" {
		stan.UnavailableReason = "runbook nie odpowiedzial dokumentem JSON"
		return stan, fmt.Errorf("runbook %s nie odpowiedzial dokumentem JSON", zlecenie.Runbook)
	}
	var odpowiedz odpowiedzRunbooka
	if err := json.Unmarshal([]byte(linia), &odpowiedz); err != nil {
		stan.UnavailableReason = "nie rozpoznano odpowiedzi runbooka: " + err.Error()
		return stan, err
	}
	for _, wpis := range odpowiedz.Snapshots {
		snapshot := Snapshot{ID: wpis.ID, Paths: wpis.Paths}
		if chwila, err := time.Parse(time.RFC3339, wpis.Time); err == nil {
			snapshot.Time = chwila.UTC()
		}
		if wpis.SizeBytes > 0 {
			rozmiar := wpis.SizeBytes
			snapshot.SizeBytes = &rozmiar
		}
		stan.Snapshots = append(stan.Snapshots, snapshot)
	}
	PosortujSnapshoty(stan.Snapshots)
	stan.LastSuccessAt = OstatniUdany(stan.Snapshots)
	if odpowiedz.TotalSizeBytes > 0 {
		rozmiar := odpowiedz.TotalSizeBytes
		stan.TotalSizeBytes = &rozmiar
	}
	return stan, nil
}

// Wykonaj zleca runbookowi zrobienie kopii.
func (r *Runbook) Wykonaj(ctx context.Context, zlecenie Zlecenie, postep PostepFunc) (Wynik, error) {
	return r.wynikOperacji(ctx, zlecenie, OperacjaBackup, postep)
}

// Sprawdz zleca runbookowi weryfikacje kopii.
func (r *Runbook) Sprawdz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	return r.wynikOperacji(ctx, zlecenie, OperacjaSprawdz, nil)
}

// Odtworz zleca runbookowi odtworzenie kopii.
func (r *Runbook) Odtworz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	return r.wynikOperacji(ctx, zlecenie, OperacjaOdtworzen, nil)
}

func (r *Runbook) wynikOperacji(ctx context.Context, zlecenie Zlecenie,
	operacja string, postep PostepFunc) (Wynik, error) {
	wynik := Wynik{}
	linia, uruchomienie, err := r.wywolaj(ctx, zlecenie, operacja, postep)
	wynik.Output = uruchomienie.Stdout + uruchomienie.Stderr
	if err != nil {
		return wynik, err
	}
	if linia == "" {
		// Milczenie po operacji zmieniajacej stan jest gorsze niz blad:
		// nie wiadomo, czy kopia powstala.
		return wynik, fmt.Errorf("runbook %s nie odpowiedzial dokumentem JSON", zlecenie.Runbook)
	}
	var odpowiedz odpowiedzRunbooka
	if err := json.Unmarshal([]byte(linia), &odpowiedz); err != nil {
		return wynik, fmt.Errorf("nie rozpoznano odpowiedzi runbooka: %w", err)
	}
	wynik.SnapshotID = odpowiedz.SnapshotID
	wynik.Message = odpowiedz.Message
	if odpowiedz.BytesAdded > 0 {
		wartosc := odpowiedz.BytesAdded
		wynik.BytesAdded = &wartosc
	}
	if odpowiedz.FilesNew > 0 {
		wartosc := odpowiedz.FilesNew
		wynik.FilesNew = &wartosc
	}
	if odpowiedz.FilesRestored > 0 {
		wartosc := odpowiedz.FilesRestored
		wynik.FilesRestored = &wartosc
	}
	if odpowiedz.DurationSeconds > 0 {
		wartosc := odpowiedz.DurationSeconds
		wynik.DurationSeconds = &wartosc
	}
	if wynik.Message == "" {
		wynik.Message = "runbook " + zlecenie.Runbook + " zakonczyl operacje " + operacja
	}
	return wynik, nil
}

// WykazRunbookow wylicza skrypty, ktore panel moze uruchomic na tym hoscie.
//
// Zwracamy takze informacje, czy katalog dalo sie odczytac: katalog bez
// runbookow i katalog nieodczytany to dwie rozne odpowiedzi.
func WykazRunbookow() ([]string, bool) {
	wpisy, err := os.ReadDir(KatalogRunbookow)
	if err != nil {
		return nil, false
	}
	runbook := &Runbook{}
	var nazwy []string
	for _, wpis := range wpisy {
		if wpis.IsDir() {
			continue
		}
		// Pokazujemy wylacznie te, ktore panel naprawde uruchomi: skrypt
		// zapisywalny poza rootem nie jest runbookiem, tylko luka.
		if _, err := runbook.Sciezka(wpis.Name()); err != nil {
			continue
		}
		nazwy = append(nazwy, wpis.Name())
	}
	return nazwy, true
}
