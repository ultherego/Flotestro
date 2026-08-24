package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func szyfrTestowy(t *testing.T) *Szyfr {
	t.Helper()
	sciezka := filepath.Join(t.TempDir(), "klucz")
	szyfr, utworzony, err := OtworzSzyfr(sciezka)
	if err != nil {
		t.Fatal(err)
	}
	if !utworzony {
		t.Fatal("klucz istnial przed pierwszym otwarciem")
	}
	return szyfr
}

// Klucz lezy w pliku poza baza: to on, a nie kolumna, decyduje o tym, czy
// z szyfrogramu da sie cokolwiek odczytac.
func TestKluczZyjeWPlikuIWracaTenSam(t *testing.T) {
	sciezka := filepath.Join(t.TempDir(), "klucz")
	pierwszy, utworzony, err := OtworzSzyfr(sciezka)
	if err != nil || !utworzony {
		t.Fatalf("pierwsze otwarcie: %v, utworzony=%v", err, utworzony)
	}
	informacje, err := os.Stat(sciezka)
	if err != nil {
		t.Fatal(err)
	}
	// Klucz czytelny dla wszystkich nie jest kluczem.
	if informacje.Mode().Perm() != 0o600 {
		t.Errorf("prawa pliku klucza = %v", informacje.Mode().Perm())
	}

	nonce, szyfrogram, err := pierwszy.Zaszyfruj([]byte("tajne"))
	if err != nil {
		t.Fatal(err)
	}
	drugi, utworzony, err := OtworzSzyfr(sciezka)
	if err != nil || utworzony {
		t.Fatalf("drugie otwarcie: %v, utworzony=%v", err, utworzony)
	}
	wartosc, err := drugi.Odszyfruj(nonce, szyfrogram)
	if err != nil || string(wartosc) != "tajne" {
		t.Fatalf("odszyfrowanie: %q, %v", wartosc, err)
	}
}

// Szyfrogram bez klucza jest bezuzyteczny - i o to chodzi w calym magazynie.
func TestSzyfrogramNieOtwieraSieInnymKluczem(t *testing.T) {
	pierwszy := szyfrTestowy(t)
	drugi := szyfrTestowy(t)

	nonce, szyfrogram, err := pierwszy.Zaszyfruj([]byte("klucz prywatny"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drugi.Odszyfruj(nonce, szyfrogram); err == nil {
		t.Fatal("cudzy klucz odszyfrowal wartosc")
	}
	// Ten sam tekst zaszyfrowany dwa razy daje rozne szyfrogramy: inaczej
	// dalo by sie stwierdzic, ze dwa sekrety maja te sama wartosc.
	_, drugiSzyfrogram, err := pierwszy.Zaszyfruj([]byte("klucz prywatny"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(szyfrogram, drugiSzyfrogram) {
		t.Error("dwa zaszyfrowania tej samej wartosci daly ten sam szyfrogram")
	}
}

func TestNazwaIWartoscMajaGranice(t *testing.T) {
	poprawne := []string{"repo.token", "backup-haslo", "ca_key1"}
	for _, nazwa := range poprawne {
		if err := WalidujNazwe(nazwa); err != nil {
			t.Errorf("nazwa %q odrzucona: %v", nazwa, err)
		}
	}
	zle := []string{"", "A", "duze.LITERY", "ze spacja", "sciezka/w/nazwie", "-startowy"}
	for _, nazwa := range zle {
		if err := WalidujNazwe(nazwa); err == nil {
			t.Errorf("nazwa %q przeszla walidacje", nazwa)
		}
	}

	if err := WalidujWartosc(nil); err == nil {
		t.Error("sekret bez wartosci przeszedl walidacje")
	}
	if err := WalidujWartosc(make([]byte, MaksymalnaWartosc+1)); err == nil {
		t.Error("wartosc ponad limit przeszla walidacje")
	}
	if err := WalidujWartosc([]byte("x")); err != nil {
		t.Errorf("jednobajtowa wartosc odrzucona: %v", err)
	}
}

// Dzierzawa jest jednorazowa i krotka: to ona, a nie sama tozsamosc hosta,
// uprawnia do pobrania wartosci.
func TestDzierzawaJestJednorazowaIKrotka(t *testing.T) {
	teraz := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	dzierzawa := Dzierzawa{IssuedAt: teraz, ExpiresAt: teraz.Add(OknoDzierzawy)}

	if !dzierzawa.Wazna(teraz.Add(time.Minute)) {
		t.Error("swieza dzierzawa uznana za niewazna")
	}
	if dzierzawa.Wazna(teraz.Add(OknoDzierzawy + time.Second)) {
		t.Error("wygasla dzierzawa uznana za wazna")
	}

	zuzyta := dzierzawa
	chwila := teraz.Add(time.Minute)
	zuzyta.RedeemedAt = &chwila
	if zuzyta.Wazna(teraz.Add(2 * time.Minute)) {
		t.Error("zuzyta dzierzawa uznana za wazna")
	}

	cofnieta := dzierzawa
	cofnieta.RevokedAt = &chwila
	if cofnieta.Wazna(teraz.Add(2 * time.Minute)) {
		t.Error("cofnieta dzierzawa uznana za wazna")
	}
}

// Sekret bez wersji albo wycofany nie jest sekretem do wydania.
func TestWydawalnoscSekretu(t *testing.T) {
	if (Secret{CurrentVersion: 0}).Wydawalny() {
		t.Error("sekret bez wersji uznany za wydawalny")
	}
	chwila := time.Now()
	if (Secret{CurrentVersion: 2, RetiredAt: &chwila}).Wydawalny() {
		t.Error("wycofany sekret uznany za wydawalny")
	}
	if !(Secret{CurrentVersion: 2}).Wydawalny() {
		t.Error("sekret z wersja uznany za niewydawalny")
	}
}
