package certificates

import (
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Wykonawca uruchamia narzedzie hosta. Wstrzykniecie zamiast wywolania
// wprost pozwala sprawdzic parsowanie bez hosta z certmongerem.
type Wykonawca func(ctx context.Context, nazwa string, argumenty ...string) (string, error)

// Cel wskazuje plik do obejrzenia wraz z tym, co panel o nim juz wie.
//
// Sciezka klucza i nazwa uslugi nie sa zgadywane z nazwy katalogu: wpisuje je
// czlowiek, ktory wie, co czyta co. Panel, ktory by je zgadywal, pokazywalby
// powiazania wygladajace na sprawdzone, a bedace domyslem.
type Cel struct {
	Path    string `json:"path"`
	KeyPath string `json:"key_path,omitempty"`
	Service string `json:"service,omitempty"`
}

// Skanuj czyta wskazane pliki bez uprawnien roota.
//
// Zakres jest dokladnie taki, jaki przyszedl w zleceniu, powiekszony pozniej
// o to, co host wie o sobie sam - czyli o zlecenia certmongera. Modul nie
// przeszukuje systemu plikow, wiec nie znajdzie certyfikatu, o ktorym nikt
// nie powiedzial; to jest cena za to, ze nie zaglada tam, gdzie nie powinien.
func Skanuj(cele []Cel) Snapshot {
	snapshot := Snapshot{
		ObservedAt: time.Now().UTC(),
		Missing:    map[string]string{},
	}

	for _, cel := range cele {
		snapshot.Scanned = append(snapshot.Scanned, cel.Path)
		snapshot.Certificates = append(snapshot.Certificates, obejrzyj(cel, snapshot.Missing))
		if len(snapshot.Certificates) >= MaksymalnaLiczbaCertyfikatow {
			break
		}
	}

	// Stan zlecen certmongera wymaga roota, ale samo pytanie "czy na tym
	// hoscie w ogole cos pilnuje certyfikatow" ma odpowiedz bez niego:
	// host bez narzedzia nie ma czego sledzic i nie jest to stan nieznany.
	if !MaCertmonger() {
		snapshot.TrackingKnown = true
		snapshot.TrackingReason = "this host does not run certmonger"
		for i := range snapshot.Certificates {
			if snapshot.Certificates[i].UnavailableReason == "" {
				snapshot.Certificates[i].Renewal = OdnawianieReczne
			}
		}
	} else {
		snapshot.Missing[FaktSledzenie] = "certmonger request list requires root"
	}

	// Klucz prywatny lezy w katalogu zamknietym dla wszystkich poza usluga,
	// wiec nawet jego prawa dostepu widzi tylko root. Brak wiedzy o kluczu
	// nie jest tym samym, co klucz, ktorego nie ma.
	if potrzebneKlucze(cele) {
		snapshot.Missing[FaktMetadaneKluczy] = "private key metadata requires root"
	} else {
		snapshot.KeysKnown = true
	}
	return snapshot
}

// potrzebneKlucze mowi, czy ktorykolwiek cel wskazuje klucz.
func potrzebneKlucze(cele []Cel) bool {
	for _, cel := range cele {
		if cel.KeyPath != "" {
			return true
		}
	}
	return false
}

// MaCertmonger mowi, czy na hoscie jest narzedzie certmongera.
func MaCertmonger() bool {
	return SciezkaNarzedzia() != ""
}

// SciezkaNarzedzia zwraca sciezke do getcert albo pusty napis.
func SciezkaNarzedzia() string {
	for _, sciezka := range []string{SciezkaGetcert, SciezkaGetcertAlt} {
		if info, err := os.Stat(sciezka); err == nil && !info.IsDir() {
			return sciezka
		}
	}
	return ""
}

// obejrzyj czyta jeden plik i sklada z niego opis certyfikatu.
func obejrzyj(cel Cel, brakujace map[string]string) Certyfikat {
	opis := Certyfikat{
		Path:         cel.Path,
		OwnerService: cel.Service,
		Source:       ZrodloZewnetrzne,
		Renewal:      OdnawianieNieznane,
	}
	if cel.KeyPath != "" {
		opis.Key = &MetadaneKlucza{Path: cel.KeyPath, Reason: "not read yet"}
	}
	if err := WalidujSciezke(cel.Path); err != nil {
		opis.UnavailableReason = err.Error()
		return opis
	}

	dane, err := CzytajPlik(cel.Path)
	if err != nil {
		opis.UnavailableReason = err.Error()
		// Plik, ktorego agent nie moze otworzyc, nie jest plikiem, ktorego
		// nie ma: certyfikat uslugi bywa trzymany w katalogu zamknietym dla
		// wszystkich poza nia. O tresc pyta wtedy helper, po nazwie pliku.
		if errors.Is(err, os.ErrPermission) {
			brakujace[FaktTrescPliku] = "certificate files are not readable without root"
		}
		return opis
	}

	certy, err := ParsujPEM(dane)
	if err != nil {
		opis.UnavailableReason = err.Error()
		return opis
	}
	zebrany := Opisz(cel.Path, certy)
	zebrany.OwnerService = cel.Service
	zebrany.Key = opis.Key
	return zebrany
}

// CzytajPlik czyta plik certyfikatu z gornym ograniczeniem rozmiaru.
//
// Otwarcie idzie z O_NOFOLLOW: sciezka certyfikatu bywa dowiazaniem, ale
// dowiazanie moze tez wskazywac gdziekolwiek indziej - a modul czytalby
// wtedy plik, ktorego nikt mu nie wskazal.
func CzytajPlik(sciezka string) ([]byte, error) {
	uchwyt, err := os.OpenFile(sciezka, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer uchwyt.Close()
	info, err := uchwyt.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("sciezka nie wskazuje zwyklego pliku")
	}
	if info.Size() > MaksymalnyRozmiarPliku {
		return nil, errors.New("plik jest wiekszy niz " +
			strconv.Itoa(MaksymalnyRozmiarPliku) + " bajtow; to nie jest certyfikat")
	}
	return io.ReadAll(io.LimitReader(uchwyt, MaksymalnyRozmiarPliku))
}

// OpiszKlucz zbiera metadane klucza prywatnego bez czytania jego tresci.
func OpiszKlucz(sciezka string) MetadaneKlucza {
	opis := MetadaneKlucza{Path: sciezka}
	info, err := os.Lstat(sciezka)
	if err != nil {
		if os.IsNotExist(err) {
			// Brak pliku jest odpowiedzia, a nie bledem odczytu: usluga
			// z certyfikatem bez klucza nie wstanie i operator ma to widziec.
			return opis
		}
		opis.Reason = err.Error()
		return opis
	}
	opis.Exists = true
	opis.Mode = strconv.FormatUint(uint64(info.Mode().Perm()), 8)
	if len(opis.Mode) < 4 {
		opis.Mode = "0000"[:4-len(opis.Mode)] + opis.Mode
	}
	opis.WorldReadable = info.Mode().Perm()&0o004 != 0
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		opis.Owner = nazwaUzytkownika(int(stat.Uid))
		opis.Group = nazwaGrupy(int(stat.Gid))
	}
	return opis
}

func nazwaUzytkownika(uid int) string {
	if wpis, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return wpis.Username
	}
	return strconv.Itoa(uid)
}

func nazwaGrupy(gid int) string {
	if wpis, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return wpis.Name
	}
	return strconv.Itoa(gid)
}

// ZbierzUzupelnienie odczytuje fakty, o ktore agent poprosil po nazwie.
//
// Helper nie dostaje polecenia "przeczytaj plik" ani "uruchom narzedzie":
// dostaje liste nazw faktow i liste celow, ktore panel juz raz zatwierdzil,
// a kazda sciezke sprawdza ponownie wlasna regula.
func ZbierzUzupelnienie(ctx context.Context, uruchom Wykonawca,
	fakty []string, cele []Cel) Uzupelnienie {
	dodatki := Uzupelnienie{Errors: map[string]string{}}

	for _, fakt := range fakty {
		switch fakt {
		case FaktMetadaneKluczy:
			dodatki.Keys = map[string]MetadaneKlucza{}
			for _, cel := range cele {
				if cel.KeyPath == "" {
					continue
				}
				if err := WalidujSciezke(cel.KeyPath); err != nil {
					dodatki.Keys[cel.KeyPath] = MetadaneKlucza{Path: cel.KeyPath, Reason: err.Error()}
					continue
				}
				dodatki.Keys[cel.KeyPath] = OpiszKlucz(cel.KeyPath)
			}

		case FaktTrescPliku:
			dodatki.Files = map[string]string{}
			for _, cel := range cele {
				if err := WalidujSciezke(cel.Path); err != nil {
					dodatki.Errors[cel.Path] = err.Error()
					continue
				}
				dane, err := CzytajPlik(cel.Path)
				if err != nil {
					dodatki.Errors[cel.Path] = err.Error()
					continue
				}
				dodatki.Files[cel.Path] = string(dane)
			}

		case FaktSledzenie:
			narzedzie := SciezkaNarzedzia()
			if narzedzie == "" {
				dodatki.TrackingKnown = true
				dodatki.TrackingReason = "this host does not run certmonger"
				continue
			}
			wyjscie, err := uruchom(ctx, narzedzie, "list")
			if err != nil {
				dodatki.Errors[FaktSledzenie] = err.Error()
				continue
			}
			dodatki.Tracking = ParsujGetcert(wyjscie)
			dodatki.TrackingKnown = true
		}
	}
	return dodatki
}

// Uzupelnij wstawia fakty helpera do obrazu zebranego bez roota.
func (s Snapshot) Uzupelnij(dodatki Uzupelnienie) Snapshot {
	if dodatki.Keys != nil {
		delete(s.Missing, FaktMetadaneKluczy)
		s.KeysKnown = true
		for i := range s.Certificates {
			klucz := s.Certificates[i].Key
			if klucz == nil {
				continue
			}
			if metadane, znany := dodatki.Keys[klucz.Path]; znany {
				s.Certificates[i].Key = &metadane
			}
		}
	}

	if dodatki.Files != nil {
		for sciezka, tresc := range dodatki.Files {
			certy, err := ParsujPEM([]byte(tresc))
			if err != nil {
				continue
			}
			for i := range s.Certificates {
				if s.Certificates[i].Path != sciezka {
					continue
				}
				zebrany := Opisz(sciezka, certy)
				zebrany.OwnerService = s.Certificates[i].OwnerService
				zebrany.Key = s.Certificates[i].Key
				s.Certificates[i] = zebrany
			}
		}
		if len(dodatki.Files) > 0 {
			delete(s.Missing, FaktTrescPliku)
		}
	}

	if dodatki.TrackingKnown {
		delete(s.Missing, FaktSledzenie)
		s.TrackingKnown = true
		s.TrackingReason = dodatki.TrackingReason
		for i := range s.Certificates {
			if s.Certificates[i].UnavailableReason != "" {
				continue
			}
			sledzenie, sledzony := dodatki.Tracking[s.Certificates[i].Path]
			if !sledzony {
				s.Certificates[i].Renewal = OdnawianieReczne
				continue
			}
			kopia := sledzenie
			s.Certificates[i].Tracking = &kopia
			s.Certificates[i].Renewal = OdnawianieSledzone
			s.Certificates[i].Source = ZrodloCertmonger
			if s.Certificates[i].Key == nil && sledzenie.KeyPath != "" {
				s.Certificates[i].Key = &MetadaneKlucza{
					Path:   sledzenie.KeyPath,
					Reason: "key is managed by certmonger",
				}
			}
		}
	}

	for nazwa, powod := range dodatki.Errors {
		if s.Missing == nil {
			s.Missing = map[string]string{}
		}
		s.Missing[nazwa] = powod
	}
	return s
}

// DodajSledzone doklada do zakresu certyfikaty, ktorych pilnuje certmonger.
//
// Host wie o nich sam, wiec panel nie musi ich konfigurowac - a bez nich
// zakladka pokazywalaby pustke na hoscie, ktory ma wlasny certyfikat
// domenowy i odnawia go od miesiecy.
func DodajSledzone(cele []Cel, sledzenia map[string]Sledzenie) []Cel {
	znane := map[string]bool{}
	for _, cel := range cele {
		znane[cel.Path] = true
	}
	for sciezka, sledzenie := range sledzenia {
		if sciezka == "" || znane[sciezka] {
			continue
		}
		if WalidujSciezke(sciezka) != nil {
			continue
		}
		cele = append(cele, Cel{Path: sciezka, KeyPath: sledzenie.KeyPath})
		znane[sciezka] = true
	}
	return cele
}

// wlascicielPliku odczytuje identyfikatory wlasciciela z metadanych pliku.
func wlascicielPliku(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok {
		return -1, -1, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
