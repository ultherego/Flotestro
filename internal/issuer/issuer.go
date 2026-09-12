// Package issuer oddziela wystawianie certyfikatow floty od tego, gdzie lezy
// klucz urzedu.
//
// Dzis klucz CA jest plikiem, ktory panel czyta przy starcie. Kiedys moze
// lezec w HSM albo w zdalnej usludze podpisujacej - i wtedy zmienia sie
// wylacznie implementacja tego interfejsu. Protokol agenta, kontrakt
// enrollmentu i reguly zakresu zostaja te same, bo nie wiedza, czym jest
// podpisujacy.
//
// Rozdzielenie jest tez granica testow: usluge da sie sprawdzic z wystawca,
// ktory zawodzi na zadanie, bez budowania calego PKI.
package issuer

import (
	"context"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// Certyfikat jest wystawionym certyfikatem tozsamosci floty.
//
// Typ jest wlasny, a nie zapozyczony z pki: uslugi maja zalezec od tego
// kontraktu, a nie od struktury urzedu certyfikacji.
type Certyfikat struct {
	PEM         []byte
	Serial      string
	Fingerprint []byte
	NotBefore   time.Time
	NotAfter    time.Time
	CommonName  string
	// Wystawca pozwala policzyc, ilu hostow dotyczy wycofanie danego CA.
	IssuerSubject string
	IssuerSerial  string
	// Nazwy sieciowe wystawione w certyfikacie. Puste dla hostow: tylko
	// relay wystepuje wobec kogokolwiek jako serwer.
	DNSNames    []string
	IPAddresses []string
}

// Wystawca podpisuje wnioski tozsamosci floty i opisuje, komu panel ufa.
//
// Kontekst jest w podpisie od poczatku, choc dzisiejsza implementacja go nie
// potrzebuje: podpis w HSM albo w zdalnej usludze jest wywolaniem sieciowym
// i musi dac sie przerwac razem z zadaniem, ktore go zamowilo.
type Wystawca interface {
	// PodpiszHosta wystawia certyfikat hosta. Tozsamosc nadaje panel:
	// wszystko z wniosku poza kluczem publicznym jest ignorowane.
	PodpiszHosta(ctx context.Context, csrPEM []byte, hostID string) (*Certyfikat, error)
	// PodpiszRelay wystawia certyfikat relaya. Nazwy sieciowe pochodza
	// z rejestru panelu; puste znaczy "wez je z wniosku", co jest dozwolone
	// wylacznie przy pierwszej rejestracji.
	PodpiszRelay(ctx context.Context, csrPEM []byte, relayID string, nazwy []string) (*Certyfikat, error)
	// Zaufanie zwraca bundle CA floty obowiazujacy teraz.
	Zaufanie(ctx context.Context) ([]byte, error)
}

// ZZaufania buduje wystawce nad urzedem certyfikacji panelu.
//
// Trust jest czytany przy kazdym podpisie, a nie kopiowany przy tworzeniu:
// rotacja CA zmienia aktywny urzad w trakcie pracy i wystawca ma o tym
// wiedziec bez restartu panelu.
func ZZaufania(trust *pki.Trust) Wystawca { return &lokalny{trust: trust} }

// lokalny podpisuje kluczem, ktory panel trzyma u siebie.
type lokalny struct {
	trust *pki.Trust
}

func (l *lokalny) PodpiszHosta(_ context.Context, csrPEM []byte, hostID string) (*Certyfikat, error) {
	wydany, err := l.trust.Active().SignAgentCSR(csrPEM, hostID)
	if err != nil {
		return nil, err
	}
	return zPKI(wydany), nil
}

func (l *lokalny) PodpiszRelay(_ context.Context, csrPEM []byte, relayID string,
	nazwy []string) (*Certyfikat, error) {
	var wydany *pki.IssuedCert
	var err error
	if len(nazwy) == 0 {
		wydany, err = l.trust.Active().SignRelayCSR(csrPEM, relayID)
	} else {
		wydany, err = l.trust.Active().SignRelayCSRWithNames(csrPEM, relayID, nazwy)
	}
	if err != nil {
		return nil, err
	}
	return zPKI(wydany), nil
}

func (l *lokalny) Zaufanie(context.Context) ([]byte, error) { return l.trust.Bundle(), nil }

func zPKI(wydany *pki.IssuedCert) *Certyfikat {
	return &Certyfikat{
		PEM: wydany.PEM, Serial: wydany.Serial, Fingerprint: wydany.Fingerprint,
		NotBefore: wydany.NotBefore, NotAfter: wydany.NotAfter,
		CommonName:    wydany.CommonName,
		IssuerSubject: wydany.IssuerSubject, IssuerSerial: wydany.IssuerSerial,
		DNSNames: wydany.DNSNames, IPAddresses: wydany.IPAddresses,
	}
}
