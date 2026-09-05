package packages

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// pakietKlucza sklada minimalny pakiet klucza publicznego w wersji 4:
// wersja, znacznik czasu, algorytm i material klucza. Do policzenia odcisku
// nie potrzeba wiecej, a wlasny pakiet pozwala sprawdzic rachunek bez
// wklejania cudzego klucza do testu.
func pakietKlucza() []byte {
	tresc := []byte{4, 0x66, 0x00, 0x00, 0x00, 1}
	tresc = append(tresc, make([]byte, 20)...)
	return tresc
}

func ramka(dane []byte) string {
	naglowek := []byte{0xc0 | 6, byte(len(dane))}
	pelne := append(naglowek, dane...)
	zakodowane := base64.StdEncoding.EncodeToString(pelne)
	return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
		zakodowane + "\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n"
}

func TestOdciskKluczaLiczySHA1PoPrefiksie(t *testing.T) {
	pakiet := pakietKlucza()
	odcisk, err := OdciskKlucza(ramka(pakiet))
	if err != nil {
		t.Fatalf("OdciskKlucza: %v", err)
	}

	suma := sha1.New()
	suma.Write([]byte{0x99, byte(len(pakiet) >> 8), byte(len(pakiet))})
	suma.Write(pakiet)
	oczekiwany := strings.ToUpper(hex.EncodeToString(suma.Sum(nil)))
	if odcisk != oczekiwany {
		t.Fatalf("odcisk = %s, oczekiwano %s", odcisk, oczekiwany)
	}
	if len(odcisk) != 40 {
		t.Fatalf("odcisk klucza v4 ma %d znakow", len(odcisk))
	}
}

func TestOdciskKluczaOdrzucaCoNieJestKluczem(t *testing.T) {
	zle := map[string]string{
		"pusty":             "",
		"bez ramki":         "to nie jest klucz",
		"pusta ramka":       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----",
		"popsuty base64":    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----",
		"certyfikat":        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"pakiet bez klucza": ramka([]byte{}),
	}
	for nazwa, material := range zle {
		if _, err := OdciskKlucza(material); err == nil {
			t.Errorf("%s: material zostal przyjety jako klucz", nazwa)
		}
	}

	// Wersji, ktorej nie znamy, nie zgadujemy: bledny odcisk jest gorszy niz
	// jego brak, bo czlowiek uznalby go za zgodny z odciskiem dostawcy.
	nieznanaWersja := append([]byte{9}, make([]byte, 10)...)
	if _, err := OdciskKlucza(ramka(nieznanaWersja)); err == nil {
		t.Error("klucz w nieznanej wersji dostal odcisk")
	}
}
