package identitystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Klucz jest kluczem prywatnym tozsamosci floty.
//
// Interfejs, a nie bajty, bo klucz nie zawsze da sie wyeksportowac. Dzis
// agent generuje go programowo i zapisuje w PEM; w profilu sprzetowym klucz
// powstaje w ukladzie TPM i nigdy go nie opuszcza - na dysk idzie wtedy
// wylacznie uchwyt. Magazyn generacji nie moze zakladac ani jednego, ani
// drugiego, bo to zalozenie przeszloby stad do enrollmentu i do odnawiania.
type Klucz interface {
	// Publiczny zwraca klucz publiczny. Tyle wystarczy, zeby zlozyc wniosek
	// o certyfikat i zeby sprawdzic, ze certyfikat pasuje do klucza.
	Publiczny() crypto.PublicKey
	// Signer podpisuje wnioski i uscisk TLS, nie oddajac materialu.
	Signer() crypto.Signer
	// Zapisz utrwala klucz w katalogu generacji.
	Zapisz(katalog string) error
}

// ZrodloKlucza tworzy i wczytuje klucze tozsamosci.
//
// Zrodlo jest wymienne: profil sprzetowy podmienia je w calosci, a reszta
// agenta nie zmienia sie wcale.
type ZrodloKlucza interface {
	Nowy() (Klucz, error)
	Wczytaj(katalog string) (Klucz, error)
}

// ErrKluczNieDoOdczytu oznacza klucz, ktorego nie da sie wyeksportowac.
// Nie jest bledem sam w sobie: tak wlasnie zachowuje sie klucz sprzetowy.
var ErrKluczNieDoOdczytu = errors.New("key_not_exportable")

// Programowe zwraca zrodlo klucza trzymanego w pliku.
//
// Domyslne i jedyne dzisiaj. Nazwa mowi wprost, ze klucz jest programowy,
// zeby profil sprzetowy nie musial sie nazywac "ten drugi".
func Programowe() ZrodloKlucza { return zrodloProgramowe{} }

type zrodloProgramowe struct{}

func (zrodloProgramowe) Nowy() (Klucz, error) {
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &kluczProgramowy{klucz: klucz}, nil
}

func (zrodloProgramowe) Wczytaj(katalog string) (Klucz, error) {
	tresc, err := os.ReadFile(filepath.Join(katalog, NazwaKlucza))
	if err != nil {
		return nil, err
	}
	return KluczZPEM(tresc)
}

// KluczZPEM czyta klucz zapisany w PEM.
func KluczZPEM(kluczPEM []byte) (Klucz, error) {
	blok, _ := pem.Decode(kluczPEM)
	if blok == nil {
		return nil, fmt.Errorf("%w: brak bloku PEM", ErrParaKluczy)
	}
	if klucz, err := x509.ParseECPrivateKey(blok.Bytes); err == nil {
		return &kluczProgramowy{klucz: klucz, pem: kluczPEM}, nil
	}
	prywatny, err := x509.ParsePKCS8PrivateKey(blok.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	signer, ok := prywatny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: klucz nie umie podpisywac", ErrParaKluczy)
	}
	return &kluczProgramowy{klucz: signer, pem: kluczPEM}, nil
}

// kluczProgramowy trzyma klucz w pamieci procesu i zapisuje go w pliku.
type kluczProgramowy struct {
	klucz crypto.Signer
	pem   []byte
}

func (k *kluczProgramowy) Publiczny() crypto.PublicKey { return k.klucz.Public() }
func (k *kluczProgramowy) Signer() crypto.Signer       { return k.klucz }

func (k *kluczProgramowy) Zapisz(katalog string) error {
	tresc, err := k.materialPEM()
	if err != nil {
		return err
	}
	// Klucz jest czytelny wylacznie dla wlasciciela. Certyfikat i bundle nie
	// sa tajne, ale ten plik jest cala tozsamoscia hosta.
	return zapiszZSync(filepath.Join(katalog, NazwaKlucza), tresc, 0o600)
}

func (k *kluczProgramowy) materialPEM() ([]byte, error) {
	if len(k.pem) > 0 {
		return k.pem, nil
	}
	prywatny, ok := k.klucz.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: nieobslugiwany rodzaj klucza", ErrParaKluczy)
	}
	der, err := x509.MarshalECPrivateKey(prywatny)
	if err != nil {
		return nil, err
	}
	k.pem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return k.pem, nil
}

// Wniosek sklada CSR podpisany danym kluczem.
//
// Podmiot i nazwy sa wskazowka: tozsamosc nadaje panel na podstawie tokenu
// albo obecnego certyfikatu, a nie tego, co host o sobie napisze. Wyjatkiem
// sa nazwy sieciowe relaya, ktore panel bierze z wniosku przy pierwszej
// rejestracji - bo wtedy nie ma ich jeszcze w rejestrze.
func Wniosek(klucz Klucz, nazwa string, dns []string, adresy []net.IP) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: nazwa},
		DNSNames:    dns,
		IPAddresses: adresy,
	}, klucz.Signer())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
