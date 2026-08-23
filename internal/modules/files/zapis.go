package files

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Odcisk liczy skrot tresci pliku.
func Odcisk(tresc []byte) string {
	suma := sha256.Sum256(tresc)
	return hex.EncodeToString(suma[:])
}

// WalidujTryb sprawdza prawa dostepu podane jako liczba osemkowa.
func WalidujTryb(tryb string) (os.FileMode, error) {
	if tryb == "" {
		return 0, nil
	}
	wartosc, err := strconv.ParseUint(tryb, 8, 32)
	if err != nil || wartosc > 0o7777 {
		return 0, fmt.Errorf("nieprawidlowe prawa dostepu %q", tryb)
	}
	// Plik konfiguracyjny zapisywalny dla wszystkich jest droga do zmiany
	// zachowania uslugi przez kazdego uzytkownika hosta.
	if wartosc&0o002 != 0 {
		return 0, fmt.Errorf("prawa %q pozwalaja zapis kazdemu uzytkownikowi hosta", tryb)
	}
	if wartosc&0o4000 != 0 || wartosc&0o2000 != 0 {
		return 0, fmt.Errorf("prawa %q ustawiaja setuid albo setgid", tryb)
	}
	return os.FileMode(wartosc), nil
}

// Wlasciciel zwraca identyfikatory uzytkownika i grupy.
//
// Puste nazwy oznaczaja "zostaw jak jest": panel nie przepisuje wlasciciela
// pliku, o ktorego wlasciciela nikt nie prosil.
func Wlasciciel(uzytkownik, grupa string) (int, int, error) {
	uid, gid := -1, -1
	if uzytkownik != "" {
		wpis, err := user.Lookup(uzytkownik)
		if err != nil {
			return 0, 0, fmt.Errorf("uzytkownik %q nie istnieje na tym hoscie", uzytkownik)
		}
		uid, _ = strconv.Atoi(wpis.Uid)
	}
	if grupa != "" {
		wpis, err := user.LookupGroup(grupa)
		if err != nil {
			return 0, 0, fmt.Errorf("grupa %q nie istnieje na tym hoscie", grupa)
		}
		gid, _ = strconv.Atoi(wpis.Gid)
	}
	return uid, gid, nil
}

// ZapiszAtomowo zapisuje plik tak, zeby nikt nie zobaczyl go w polowie.
//
// Kolejnosc ma znaczenie i jest tu cala trescia: prawa i wlasciciel sa
// ustawiane na nowym pliku, zanim zajmie on miejsce starego. Odwrotna
// kolejnosc zostawia okno, w ktorym plik konfiguracyjny stoi juz na swoim
// miejscu z prawami domyslnymi - a to wystarczy, zeby ktos go przeczytal
// albo podmienil.
//
// Na koniec synchronizujemy plik i katalog: bez tego zmiana ginie przy zaniku
// zasilania, a plik konfiguracyjny czyta sie wlasnie po takim zdarzeniu.
func ZapiszAtomowo(sciezka string, tresc []byte, tryb os.FileMode, uid, gid int) error {
	katalog := filepath.Dir(sciezka)
	tymczasowy := filepath.Join(katalog, ".flotestro-"+filepath.Base(sciezka)+".nowy")
	_ = os.Remove(tymczasowy)

	trybPliku := tryb
	if trybPliku == 0 {
		trybPliku = 0o644
		if info, err := os.Stat(sciezka); err == nil {
			// Plik istniejacy zachowuje swoje prawa, gdy nikt nie prosil
			// o zmiane: zapis tresci nie jest decyzja o dostepie.
			trybPliku = info.Mode().Perm()
		}
	}

	plik, err := OtworzBezDowiazan(tymczasowy,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(trybPliku))
	if err != nil {
		return err
	}
	usunPrzyBledzie := func(err error) error {
		_ = plik.Close()
		_ = os.Remove(tymczasowy)
		return err
	}
	if _, err := plik.Write(tresc); err != nil {
		return usunPrzyBledzie(err)
	}
	// Prawa ustawiamy jawnie: umask hosta obcina tryb podany przy tworzeniu.
	if err := plik.Chmod(trybPliku); err != nil {
		return usunPrzyBledzie(err)
	}
	if uid >= 0 || gid >= 0 {
		if err := plik.Chown(uid, gid); err != nil {
			return usunPrzyBledzie(err)
		}
	}
	if err := plik.Sync(); err != nil {
		return usunPrzyBledzie(err)
	}
	if err := plik.Close(); err != nil {
		_ = os.Remove(tymczasowy)
		return err
	}

	if err := os.Rename(tymczasowy, sciezka); err != nil {
		_ = os.Remove(tymczasowy)
		return err
	}
	// Sam rename jest atomowy, ale bez synchronizacji katalogu moze nie
	// przetrwac zaniku zasilania - a wtedy zostaje stara tresc pod nowa nazwa.
	uchwyt, err := os.Open(katalog)
	if err != nil {
		return nil
	}
	defer uchwyt.Close()
	return uchwyt.Sync()
}

// OpiszPlik zbiera metadane pliku bez czytania jego tresci.
func OpiszPlik(sciezka string) Plik {
	opis := Plik{Path: sciezka}
	info, err := os.Lstat(sciezka)
	if err != nil {
		if os.IsNotExist(err) {
			return opis
		}
		opis.UnavailableReason = err.Error()
		return opis
	}
	opis.Exists = true
	opis.SizeBytes = info.Size()
	opis.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	czas := info.ModTime()
	opis.ModifiedAt = &czas
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		opis.Owner = nazwaUzytkownika(int(stat.Uid))
		opis.Group = nazwaGrupy(int(stat.Gid))
	}
	// Dowiazanie nie jest plikiem konfiguracyjnym, tylko wskazaniem na inny
	// plik. Panel go nie czyta i nie udaje, ze zna jego tresc.
	if info.Mode()&os.ModeSymlink != 0 {
		opis.UnavailableReason = "sciezka jest dowiazaniem symbolicznym"
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

// WalidujTresc sprawdza to, co da sie sprawdzic bez uruchamiania niczego.
func WalidujTresc(tresc string) error {
	if len(tresc) > MaksymalnyRozmiar {
		return fmt.Errorf("tresc jest wieksza niz %d bajtow; to nie jest plik konfiguracyjny",
			MaksymalnyRozmiar)
	}
	if strings.ContainsRune(tresc, 0) {
		return fmt.Errorf("tresc zawiera bajt zerowy; to nie jest plik tekstowy")
	}
	return nil
}
