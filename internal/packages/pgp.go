package packages

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Klucz repozytorium jest materialem publicznym, wiec panel moze go przesylac
// w zleceniu - inaczej niz haslo, ktore idzie przez magazyn sekretow. Publiczny
// nie znaczy jednak dowolny: to ten klucz rozstrzyga, czyje pakiety host
// zainstaluje. Dlatego zanim trafi na dysk, sprawdzamy, ze naprawde jest
// kluczem OpenPGP, i liczymy jego odcisk - zeby czlowiek mial co porownac
// z odciskiem podanym przez dostawce.
//
// Liczymy go sami, bez biblioteki OpenPGP: potrzebny jest jeden pakiet
// z ramki ASCII i jeden skrot, a nie caly model zaufania.

// OdciskKlucza sprawdza material klucza i zwraca odcisk klucza glownego.
func OdciskKlucza(material string) (string, error) {
	dane, err := rozpakujRamke(material)
	if err != nil {
		return "", err
	}
	pakiet, err := pierwszyKluczPubliczny(dane)
	if err != nil {
		return "", err
	}
	return odciskPakietuKlucza(pakiet)
}

// rozpakujRamke zdejmuje ramke ASCII i dekoduje tresc.
//
// Klucz podany binarnie tez jest kluczem: rozpoznajemy go po tym, ze nie ma
// naglowka ramki, i przepuszczamy dalej bez dekodowania.
func rozpakujRamke(material string) ([]byte, error) {
	przyciety := strings.TrimSpace(material)
	if przyciety == "" {
		return nil, fmt.Errorf("material klucza jest pusty")
	}
	if !strings.HasPrefix(przyciety, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return nil, fmt.Errorf("material nie jest kluczem publicznym OpenPGP w ramce ASCII")
	}
	linie := strings.Split(przyciety, "\n")
	var tresc strings.Builder
	wTresci := false
	for _, linia := range linie[1:] {
		linia = strings.TrimSpace(linia)
		switch {
		case strings.HasPrefix(linia, "-----END"):
			wTresci = false
		case !wTresci && linia == "":
			// Pusta linia konczy naglowki ramki i zaczyna tresc.
			wTresci = true
		case wTresci:
			// Suma kontrolna CRC24 zaczyna sie od znaku rownosci i nie
			// nalezy do tresci.
			if strings.HasPrefix(linia, "=") {
				continue
			}
			tresc.WriteString(linia)
		}
	}
	if tresc.Len() == 0 {
		return nil, fmt.Errorf("ramka klucza nie zawiera tresci")
	}
	dane, err := base64.StdEncoding.DecodeString(tresc.String())
	if err != nil {
		return nil, fmt.Errorf("tresc klucza nie jest poprawnym base64: %w", err)
	}
	return dane, nil
}

// pierwszyKluczPubliczny znajduje pakiet klucza glownego (tag 6).
func pierwszyKluczPubliczny(dane []byte) ([]byte, error) {
	i := 0
	for i < len(dane) {
		naglowek := dane[i]
		if naglowek&0x80 == 0 {
			return nil, fmt.Errorf("material klucza ma nieprawidlowa strukture pakietow")
		}
		var tag int
		var dlugosc int
		if naglowek&0x40 != 0 {
			// Format nowy: tag w szesciu bitach, dlugosc jedno- lub
			// wielobajtowa.
			tag = int(naglowek & 0x3f)
			i++
			if i >= len(dane) {
				return nil, fmt.Errorf("pakiet klucza jest urwany")
			}
			pierwszy := int(dane[i])
			switch {
			case pierwszy < 192:
				dlugosc = pierwszy
				i++
			case pierwszy < 224:
				if i+1 >= len(dane) {
					return nil, fmt.Errorf("pakiet klucza jest urwany")
				}
				dlugosc = (pierwszy-192)<<8 + int(dane[i+1]) + 192
				i += 2
			case pierwszy == 255:
				if i+4 >= len(dane) {
					return nil, fmt.Errorf("pakiet klucza jest urwany")
				}
				dlugosc = int(dane[i+1])<<24 | int(dane[i+2])<<16 |
					int(dane[i+3])<<8 | int(dane[i+4])
				i += 5
			default:
				// Dlugosc czesciowa wystepuje w danych strumieniowych,
				// a nie w kluczu.
				return nil, fmt.Errorf("material klucza ma nieobslugiwana dlugosc pakietu")
			}
		} else {
			tag = int(naglowek&0x3c) >> 2
			typDlugosci := int(naglowek & 0x03)
			i++
			switch typDlugosci {
			case 0:
				if i >= len(dane) {
					return nil, fmt.Errorf("pakiet klucza jest urwany")
				}
				dlugosc = int(dane[i])
				i++
			case 1:
				if i+1 >= len(dane) {
					return nil, fmt.Errorf("pakiet klucza jest urwany")
				}
				dlugosc = int(dane[i])<<8 | int(dane[i+1])
				i += 2
			case 2:
				if i+3 >= len(dane) {
					return nil, fmt.Errorf("pakiet klucza jest urwany")
				}
				dlugosc = int(dane[i])<<24 | int(dane[i+1])<<16 |
					int(dane[i+2])<<8 | int(dane[i+3])
				i += 4
			default:
				return nil, fmt.Errorf("material klucza ma nieobslugiwana dlugosc pakietu")
			}
		}
		if dlugosc < 0 || i+dlugosc > len(dane) {
			return nil, fmt.Errorf("pakiet klucza jest urwany")
		}
		if tag == 6 {
			return dane[i : i+dlugosc], nil
		}
		i += dlugosc
	}
	return nil, fmt.Errorf("material nie zawiera pakietu klucza publicznego")
}

// odciskPakietuKlucza liczy odcisk klucza glownego.
//
// Wersja 4 liczy SHA-1 po prefiksie 0x99 i dwubajtowej dlugosci; wersja 6 -
// SHA-256 po prefiksie 0x9b i czterobajtowej dlugosci. Wersji, ktorej nie
// znamy, nie zgadujemy: bledny odcisk jest gorszy niz brak odcisku, bo
// czlowiek porownalby go z odciskiem dostawcy i uznal za zgodny.
func odciskPakietuKlucza(pakiet []byte) (string, error) {
	if len(pakiet) == 0 {
		return "", fmt.Errorf("pakiet klucza jest pusty")
	}
	switch pakiet[0] {
	case 4:
		suma := sha1.New()
		suma.Write([]byte{0x99, byte(len(pakiet) >> 8), byte(len(pakiet))})
		suma.Write(pakiet)
		return strings.ToUpper(hex.EncodeToString(suma.Sum(nil))), nil
	case 6:
		suma := sha256.New()
		dlugosc := len(pakiet)
		suma.Write([]byte{0x9b, byte(dlugosc >> 24), byte(dlugosc >> 16),
			byte(dlugosc >> 8), byte(dlugosc)})
		suma.Write(pakiet)
		return strings.ToUpper(hex.EncodeToString(suma.Sum(nil))), nil
	}
	return "", fmt.Errorf("klucz w wersji %d nie jest obslugiwany", pakiet[0])
}
