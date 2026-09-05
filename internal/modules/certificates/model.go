// Package certificates opisuje certyfikaty lezace na hoscie: ich terminy,
// wystawcow, nazwy, ktore obejmuja, i usluge, ktora z nich korzysta.
//
// Modul zbiera fakty o wskazanych plikach, a nie przeszukuje hosta. Panel,
// ktory chodzi po calym systemie plikow w poszukiwaniu certyfikatow, znajduje
// przede wszystkim magazyn zaufania - kilkaset zaswiadczen urzedow, ktore nie
// naleza do zadnej uslugi - i zaglada do katalogow, w ktorych nie ma nic do
// szukania. Zakres jest wiec wyliczony: sciezki wskazane w panelu oraz to,
// co host sam o sobie wie, bo pilnuje tego certmonger.
//
// Klucza prywatnego modul nie czyta nigdy przy odczycie stanu. O kluczu wie
// tylko tyle, ile widac z zewnatrz: czy plik istnieje, jakie ma prawa i do
// kogo nalezy. Zgodnosc klucza z certyfikatem sprawdza sie dokladnie raz -
// przy wdrozeniu, gdy klucz i tak jest przez chwile w rekach hosta.
package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Zrodlo mowi, skad certyfikat na hoscie sie wzial.
const (
	// ZrodloPanel oznacza certyfikat wdrozony przez Flotestro.
	ZrodloPanel = "flotestro"
	// ZrodloCertmonger oznacza certyfikat, ktorego pilnuje demon certmonger:
	// to on go zamowil i to on go odnowi.
	ZrodloCertmonger = "certmonger"
	// ZrodloZewnetrzne oznacza plik, ktory ktos polozyl poza panelem.
	ZrodloZewnetrzne = "external"
)

// Sposob odnawiania certyfikatu.
const (
	// OdnawianieSledzone oznacza certyfikat z zleceniem certmongera: host
	// odnowi go sam, zanim wygasnie.
	OdnawianieSledzone = "tracked"
	// OdnawianieReczne oznacza certyfikat, ktorego nikt na hoscie nie
	// pilnuje - odnowienie jest decyzja czlowieka albo panelu.
	OdnawianieReczne = "manual"
	// OdnawianieNieznane oznacza stan nieustalony: nie udalo sie odczytac,
	// czy cokolwiek tego certyfikatu pilnuje. To nie to samo, co "reczne".
	OdnawianieNieznane = "unknown"
)

// Sciezki narzedzi. Certmonger jest jedynym, po ktore modul siega.
const (
	SciezkaGetcert    = "/usr/bin/getcert"
	SciezkaGetcertAlt = "/usr/sbin/getcert"
)

// MaksymalnyRozmiarPliku ogranicza plik, ktory modul w ogole otwiera.
//
// Certyfikat z lancuchem ma kilka kilobajtow. Plik wiekszy niz to nie jest
// certyfikatem, a jego wczytanie byloby wylacznie sposobem na zajecie pamieci.
const MaksymalnyRozmiarPliku = 256 << 10

// MaksymalnaLiczbaCertyfikatow ogranicza jeden odczyt.
//
// Granica dotyczy takze pojedynczego pliku: ktos moze wskazac magazyn zaufania
// jako sciezke do obejrzenia, a wtedy odpowiedz hosta bylaby lista kilkuset
// urzedow zamiast stanu jego uslug.
const MaksymalnaLiczbaCertyfikatow = 64

// MetadaneKlucza opisuje klucz prywatny bez jego tresci.
//
// Panel nie potrzebuje klucza, zeby powiedziec o nim to, co jest wazne: czy
// lezy tam, gdzie usluga go szuka, i czy nie jest czytelny dla wszystkich.
type MetadaneKlucza struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Group  string `json:"group,omitempty"`
	// WorldReadable jest wnioskiem z praw dostepu, a nie osobnym odczytem.
	WorldReadable bool `json:"world_readable,omitempty"`
	// Reason mowi, dlaczego stanu klucza nie ustalono. Brak wiedzy o kluczu
	// nie jest tym samym, co klucz, ktorego nie ma.
	Reason string `json:"reason,omitempty"`
}

// Sledzenie opisuje zlecenie certmongera dotyczace jednego certyfikatu.
type Sledzenie struct {
	Request string `json:"request,omitempty"`
	// Status jest stanem zlecenia widzianym przez demona: MONITORING oznacza
	// certyfikat pod opieka, CA_UNREACHABLE - opieke, ktora nie dziala.
	Status  string `json:"status,omitempty"`
	CA      string `json:"ca,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	// AutoRenew mowi, czy demon odnowi certyfikat sam. Zlecenie bez tego
	// wpisu jest tylko obserwacja terminu.
	AutoRenew *bool      `json:"auto_renew,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
}

// Certyfikat opisuje jeden certyfikat lezacy na hoscie.
type Certyfikat struct {
	Path    string   `json:"path"`
	Subject string   `json:"subject,omitempty"`
	Issuer  string   `json:"issuer,omitempty"`
	Serial  string   `json:"serial,omitempty"`
	SANs    []string `json:"sans,omitempty"`
	// Terminy sa wskaznikami, bo plik nieodczytany nie ma terminu zadnego.
	// Data zerowa w tym miejscu wygladalaby jak certyfikat wystawiony
	// w pierwszym roku naszej ery - czyli jak wygasly.
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	KeyAlgorithm      string     `json:"key_algorithm,omitempty"`
	KeyBits           int        `json:"key_bits,omitempty"`
	SignatureAlgo     string     `json:"signature_algorithm,omitempty"`
	SelfSigned        bool       `json:"self_signed,omitempty"`
	IsCA              bool       `json:"is_ca,omitempty"`
	// ChainLength liczy zaswiadczenia w pliku razem z lisciem. Jedynka
	// oznacza certyfikat bez lancucha - a to najczestszy powod, dla ktorego
	// klient odrzuca polaczenie mimo waznego certyfikatu.
	ChainLength int `json:"chain_length,omitempty"`

	// Klucz prywatny opisany z zewnatrz; tresci modul nie czyta.
	Key *MetadaneKlucza `json:"key,omitempty"`

	// Powiazania: czym jest ten plik dla hosta.
	Source string `json:"source"`
	// OwnerService jest jednostka, ktora ten plik czyta. Panel jej nie
	// zgaduje z nazwy katalogu: wpisuje ja czlowiek, ktory wie, co czyta co.
	OwnerService string     `json:"owner_service,omitempty"`
	Renewal      string     `json:"renewal"`
	Tracking     *Sledzenie `json:"tracking,omitempty"`

	// UnavailableReason opisuje plik, ktorego nie udalo sie odczytac albo
	// rozpoznac. Pusta lista certyfikatow w takim pliku nie jest odpowiedzia
	// "nie ma tu certyfikatu".
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// DniDoWygasniecia liczy pelne doby do konca waznosci. Wartosc ujemna
// oznacza certyfikat juz wygasly.
func (c Certyfikat) DniDoWygasniecia(teraz time.Time) *int {
	if c.NotAfter == nil {
		return nil
	}
	dni := int(c.NotAfter.Sub(teraz).Hours() / 24)
	return &dni
}

// Snapshot to obraz certyfikatow na hoscie.
type Snapshot struct {
	Certificates []Certyfikat `json:"certificates,omitempty"`
	// Scanned wylicza sciezki, o ktore panel poprosil. Bez tego pusta lista
	// certyfikatow nie odroznialaby hosta bez certyfikatow od hosta, ktorego
	// nikt jeszcze nie skonfigurowal.
	Scanned []string `json:"scanned,omitempty"`
	// TrackingKnown mowi, czy udalo sie ustalic, co pilnuje certyfikatow.
	TrackingKnown bool `json:"tracking_known"`
	// TrackingReason mowi, dlaczego nie udalo sie tego ustalic.
	TrackingReason string `json:"tracking_reason,omitempty"`
	// KeysKnown mowi, czy przy certyfikatach jest stan kluczy. Bez roota
	// katalog kluczy bywa zamkniety i wtedy odpowiedz brzmi "nie wiadomo",
	// a nie "klucza nie ma".
	KeysKnown bool `json:"keys_known"`
	// Missing wylicza fakty, ktorych nie zebrano, wraz z powodem.
	Missing map[string]string `json:"missing,omitempty"`

	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// Nazwy faktow, ktorych agent nie odczyta bez roota. Helper dostaje ich liste,
// a nie polecenie do wykonania: zakres jego pracy jest wyliczony.
const (
	FaktMetadaneKluczy = "key_metadata"
	FaktSledzenie      = "renewal_tracking"
	FaktTrescPliku     = "certificate_files"
)

// Brakujace wylicza fakty, po ktore trzeba pojsc do helpera.
func (s Snapshot) Brakujace() []string {
	var nazwy []string
	for nazwa := range s.Missing {
		nazwy = append(nazwy, nazwa)
	}
	return nazwy
}

// Uzupelnienie to fakty zebrane przez helpera na wyrazne zadanie.
//
// Puste pole oznacza fakt, o ktory nie pytano albo ktorego nie udalo sie
// odczytac - powod jest wtedy w Errors, pod nazwa faktu.
type Uzupelnienie struct {
	// Keys jest metadanymi kluczy, po sciezce klucza.
	Keys map[string]MetadaneKlucza `json:"keys,omitempty"`
	// Tracking jest stanem zlecen certmongera, po sciezce certyfikatu.
	Tracking       map[string]Sledzenie `json:"tracking,omitempty"`
	TrackingKnown  bool                 `json:"tracking_known,omitempty"`
	TrackingReason string               `json:"tracking_reason,omitempty"`
	// Targets jest lista celow, ktore host zna sam z siebie: te wpisane przez
	// panel wczesniej i te, ktorych pilnuje certmonger. Dzieki niej inwentarz
	// opisuje ten sam zakres, co ostatni skan.
	Targets []Cel `json:"targets,omitempty"`
	// Files jest trescia plikow, ktorych agent nie mogl otworzyc: certyfikat
	// bywa trzymany w katalogu zamknietym dla wszystkich poza usluga.
	Files  map[string]string `json:"files,omitempty"`
	Errors map[string]string `json:"errors,omitempty"`
}

// Odcisk liczy skrot certyfikatu w postaci DER.
//
// To ten sam odcisk, ktory pokazuje przegladarka i openssl, wiec da sie go
// porownac z tym, co widac po drugiej stronie polaczenia.
func Odcisk(cert *x509.Certificate) string {
	suma := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(suma[:])
}

// ParsujPEM wyciaga certyfikaty z pliku PEM w kolejnosci, w jakiej leza.
//
// Kolejnosc ma znaczenie: pierwszy jest lisciem uslugi, dalsze sa lancuchem.
// Plik z kluczem prywatnym w srodku nie jest bledem - bloki inne niz
// CERTIFICATE po prostu pomijamy i nigdzie ich nie przepisujemy.
func ParsujPEM(dane []byte) ([]*x509.Certificate, error) {
	var certy []*x509.Certificate
	reszta := dane
	for len(reszta) > 0 {
		var blok *pem.Block
		blok, reszta = pem.Decode(reszta)
		if blok == nil {
			break
		}
		if blok.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blok.Bytes)
		if err != nil {
			return nil, fmt.Errorf("nie rozpoznano certyfikatu: %w", err)
		}
		certy = append(certy, cert)
		if len(certy) >= MaksymalnaLiczbaCertyfikatow {
			break
		}
	}
	if len(certy) == 0 {
		return nil, fmt.Errorf("plik nie zawiera certyfikatu w formacie PEM")
	}
	return certy, nil
}

// Opisz sklada opis certyfikatu z tego, co niesie on sam.
func Opisz(sciezka string, certy []*x509.Certificate) Certyfikat {
	lisc := certy[0]
	poczatek, koniec := lisc.NotBefore.UTC(), lisc.NotAfter.UTC()
	opis := Certyfikat{
		Path:              sciezka,
		Subject:           lisc.Subject.String(),
		Issuer:            lisc.Issuer.String(),
		Serial:            lisc.SerialNumber.String(),
		SANs:              NazwyAlternatywne(lisc),
		NotBefore:         &poczatek,
		NotAfter:          &koniec,
		FingerprintSHA256: Odcisk(lisc),
		SignatureAlgo:     lisc.SignatureAlgorithm.String(),
		IsCA:              lisc.IsCA,
		ChainLength:       len(certy),
		Source:            ZrodloZewnetrzne,
		Renewal:           OdnawianieNieznane,
	}
	opis.KeyAlgorithm, opis.KeyBits = OpisKlucza(lisc.PublicKey)
	opis.SelfSigned = lisc.Subject.String() == lisc.Issuer.String()
	return opis
}

// NazwyAlternatywne zbiera wszystkie nazwy, ktore certyfikat obejmuje.
//
// Adresy, nazwy i identyfikatory URI stoja w jednej liscie z prefiksem typu:
// operator pyta "czy ten certyfikat obejmuje ten adres", a nie "w ktorym polu
// rozszerzenia jest ta nazwa".
func NazwyAlternatywne(cert *x509.Certificate) []string {
	var nazwy []string
	nazwy = append(nazwy, cert.DNSNames...)
	for _, adres := range cert.IPAddresses {
		nazwy = append(nazwy, adres.String())
	}
	nazwy = append(nazwy, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		nazwy = append(nazwy, uri.String())
	}
	return nazwy
}

// OpisKlucza nazywa algorytm i sile klucza publicznego.
func OpisKlucza(klucz crypto.PublicKey) (string, int) {
	switch typ := klucz.(type) {
	case *rsa.PublicKey:
		return "RSA", typ.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", typ.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}

// Obejmuje mowi, czy certyfikat obejmuje podana nazwe.
//
// Sprawdzenie idzie przez biblioteczna implementacje weryfikacji nazw, wiec
// wieloznacznik "*.example.com" dziala tak samo, jak zadziala u klienta.
func Obejmuje(cert *x509.Certificate, nazwa string) bool {
	return cert.VerifyHostname(nazwa) == nil
}

// DopasujKlucz sprawdza, czy klucz prywatny nalezy do certyfikatu.
//
// To jedyne miejsce w module, w ktorym klucz jest czytany - i dzieje sie to
// tuz przed wdrozeniem, gdy klucz i tak musi przejsc przez rece hosta.
// Wynikiem jest sama odpowiedz "pasuje albo nie": tresci klucza nie ma ani
// w komunikacie bledu, ani w wyniku operacji.
func DopasujKlucz(cert *x509.Certificate, kluczPEM []byte) error {
	klucz, err := ParsujKluczPrywatny(kluczPEM)
	if err != nil {
		return err
	}
	publiczny, ok := klucz.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("klucz nieznanego rodzaju")
	}
	porownywalny, ok := publiczny.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("klucza tego rodzaju nie da sie porownac z certyfikatem")
	}
	if !porownywalny.Equal(cert.PublicKey) {
		return fmt.Errorf("klucz prywatny nie nalezy do tego certyfikatu")
	}
	return nil
}

// ParsujKluczPrywatny czyta klucz w jednym z trzech uzywanych zapisow.
func ParsujKluczPrywatny(dane []byte) (crypto.PrivateKey, error) {
	reszta := dane
	for len(reszta) > 0 {
		var blok *pem.Block
		blok, reszta = pem.Decode(reszta)
		if blok == nil {
			break
		}
		if !strings.Contains(blok.Type, "PRIVATE KEY") {
			continue
		}
		// Zaszyfrowany klucz rozpoznajemy po naglowku i mowimy o tym wprost:
		// panel nie ma gdzie zapytac o haslo, a "nie rozpoznano klucza"
		// byloby mylaca odpowiedzia na inne pytanie.
		if _, zaszyfrowany := blok.Headers["DEK-Info"]; zaszyfrowany {
			return nil, fmt.Errorf("klucz jest zaszyfrowany haslem; magazyn przechowuje klucze bez hasla")
		}
		if strings.HasPrefix(blok.Type, "ENCRYPTED") {
			return nil, fmt.Errorf("klucz jest zaszyfrowany haslem; magazyn przechowuje klucze bez hasla")
		}
		if klucz, err := x509.ParsePKCS8PrivateKey(blok.Bytes); err == nil {
			return klucz, nil
		}
		if klucz, err := x509.ParsePKCS1PrivateKey(blok.Bytes); err == nil {
			return klucz, nil
		}
		if klucz, err := x509.ParseECPrivateKey(blok.Bytes); err == nil {
			return klucz, nil
		}
		return nil, fmt.Errorf("nie rozpoznano zapisu klucza prywatnego")
	}
	return nil, fmt.Errorf("dane nie zawieraja klucza prywatnego w formacie PEM")
}

// SprawdzLancuch sprawdza, czy zaswiadczenia w pliku ida w kolejnosci od
// liscia do korzenia i czy kazde jest podpisane przez nastepne.
//
// Zly porzadek lancucha jest bledem, ktory widac dopiero u klienta: serwer
// wystartuje, a polaczenie odrzuci co drugi program. Dlatego sprawdzamy to
// przed podmiana, a nie po niej.
func SprawdzLancuch(certy []*x509.Certificate) error {
	for i := 0; i+1 < len(certy); i++ {
		if err := certy[i].CheckSignatureFrom(certy[i+1]); err != nil {
			return fmt.Errorf("zaswiadczenie %d w pliku nie podpisuje poprzedniego (%s): %w",
				i+2, certy[i+1].Subject.CommonName, err)
		}
	}
	return nil
}

// SprawdzTerminy sprawdza, czy certyfikat da sie dzisiaj uzyc.
func SprawdzTerminy(cert *x509.Certificate, teraz time.Time) error {
	if teraz.Before(cert.NotBefore) {
		return fmt.Errorf("certyfikat zaczyna obowiazywac dopiero %s",
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !cert.NotAfter.After(teraz) {
		return fmt.Errorf("certyfikat stracil waznosc %s",
			cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// Katalogi, w ktorych panel wdraza certyfikaty i klucze.
//
// Lista jest waska celowo. Zapis certyfikatu w dowolne miejsce systemu plikow
// jest zapisem dowolnego pliku - a od tego jest modul plikow z wlasnymi
// zabezpieczeniami, ktory zreszta kluczy i certyfikatow nie tyka.
var dozwolonePrefiksy = []string{
	"/etc/pki/tls/",
	"/etc/pki/flotestro/",
	"/etc/ssl/private/",
	"/etc/ssl/local/",
	// Debian trzyma certyfikat serwera w tym samym katalogu, co magazyn
	// zaufania. Sam plik lezacy tam niczego jeszcze nie czyni zaufanym -
	// zaufanie daje wygenerowana wiazka i dowiazania po skrocie nazwy.
	// Dlatego katalog jest dozwolony, a te dwie rzeczy nie sa.
	"/etc/ssl/certs/",
	"/etc/nginx/",
	"/etc/httpd/",
	"/etc/apache2/",
	"/etc/postfix/",
	"/etc/dovecot/",
	"/etc/letsencrypt/live/",
	"/etc/flotestro/certs/",
	"/opt/flotestro/certs/",
}

// zakazanePrefiksy wylicza miejsca, ktorych panel nie tyka nigdy - takze
// wtedy, gdy leza wewnatrz katalogu dozwolonego.
//
// Magazyn zaufania odpowiada na inne pytanie niz certyfikat uslugi: mowi,
// komu host wierzy, a nie czym sie przedstawia. Dopisanie tam urzedu jest
// zmiana o innej wadze i nie moze wygladac jak wdrozenie certyfikatu.
var zakazanePrefiksy = []string{
	"/etc/pki/ca-trust/",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ca-certificates/",
	"/usr/share/ca-certificates/",
	"/usr/local/share/ca-certificates/",
	// Tozsamosc agenta jest osobnym podsystemem z wlasnym odnowieniem:
	// podmiana jego certyfikatu przez zwykla operacje odcielaby panel od
	// hosta w chwili, w ktorej host przestalby byc soba.
	"/etc/flotestro/agent/",
	"/var/lib/flotestro/agent/",
}

// dowiazanieSkrotu rozpoznaje nazwe, pod ktora OpenSSL szuka urzedu
// w katalogu zaufania: osiem cyfr szesnastkowych i numer kolejny. Plik pod
// taka nazwa nie jest certyfikatem uslugi - jest wpisem do magazynu zaufania.
var dowiazanieSkrotu = regexp.MustCompile(`^[0-9a-f]{8}\.[0-9]+$`)

// WalidujSciezke sprawdza, czy panel moze wskazac ten plik.
//
// Ta sama regula obowiazuje odczyt i zapis: sciezka, ktorej panel nie zapisze,
// nie jest tez sciezka, o ktorej tresc pyta. Inaczej "obejrzyj ten plik"
// byloby sposobem na czytanie dowolnego pliku hosta.
func WalidujSciezke(sciezka string) error {
	if sciezka == "" {
		return fmt.Errorf("sciezka jest pusta")
	}
	if !strings.HasPrefix(sciezka, "/") {
		return fmt.Errorf("sciezka %q nie jest bezwzgledna", sciezka)
	}
	if strings.Contains(sciezka, "..") {
		return fmt.Errorf("sciezka %q wychodzi poza wskazany katalog", sciezka)
	}
	if strings.ContainsAny(sciezka, "\n\t*?") {
		return fmt.Errorf("sciezka %q zawiera niedozwolony znak", sciezka)
	}
	if sciezka != path.Clean(sciezka) {
		return fmt.Errorf("sciezka %q nie jest w postaci znormalizowanej", sciezka)
	}
	if len(sciezka) > 4096 {
		return fmt.Errorf("sciezka jest dluzsza niz 4096 znakow")
	}
	for _, prefiks := range zakazanePrefiksy {
		if strings.HasPrefix(sciezka, prefiks) {
			return fmt.Errorf("sciezka %q nalezy do magazynu zaufania albo do tozsamosci agenta", sciezka)
		}
	}
	if dowiazanieSkrotu.MatchString(path.Base(sciezka)) {
		return fmt.Errorf("nazwa %q jest wpisem magazynu zaufania, a nie certyfikatem uslugi",
			path.Base(sciezka))
	}
	for _, prefiks := range dozwolonePrefiksy {
		if strings.HasPrefix(sciezka, prefiks) {
			return nil
		}
	}
	return fmt.Errorf("sciezka %q lezy poza katalogami certyfikatow", sciezka)
}

// WalidujCel sprawdza adres, pod ktorym panel sprawdzi wdrozony certyfikat.
//
// Sonda laczy sie z hosta, wiec adres bez portu albo z nazwa, ktorej nie da
// sie rozdzielic, zamienilby test w losowe polaczenie.
func WalidujCel(cel string) error {
	if cel == "" {
		return nil
	}
	gospodarz, port, err := net.SplitHostPort(cel)
	if err != nil {
		return fmt.Errorf("cel sondy %q nie ma postaci host:port", cel)
	}
	if gospodarz == "" {
		return fmt.Errorf("cel sondy %q nie wskazuje hosta", cel)
	}
	numer, err := strconv.Atoi(port)
	if err != nil || numer < 1 || numer > 65535 {
		return fmt.Errorf("cel sondy %q ma nieprawidlowy port", cel)
	}
	return nil
}

// WalidujJednostke sprawdza nazwe uslugi, ktora ma przeczytac nowy plik.
func WalidujJednostke(jednostka string) error {
	if jednostka == "" {
		return nil
	}
	if strings.ContainsAny(jednostka, " \t\n/;&|$`") {
		return fmt.Errorf("nazwa jednostki %q zawiera niedozwolony znak", jednostka)
	}
	if len(jednostka) > 256 {
		return fmt.Errorf("nazwa jednostki jest za dluga")
	}
	return nil
}

// WalidujZlecenie ogranicza to, co idzie do certmongera jako nazwa zlecenia.
// Wartosc pochodzi z panelu, a trafia do argumentu polecenia.
func WalidujZlecenie(zlecenie string) error {
	if zlecenie == "" {
		return fmt.Errorf("odnowienie wymaga identyfikatora zlecenia certmongera")
	}
	if len(zlecenie) > 128 {
		return fmt.Errorf("identyfikator zlecenia jest za dlugi")
	}
	for _, znak := range zlecenie {
		if znak >= 'a' && znak <= 'z' || znak >= 'A' && znak <= 'Z' ||
			znak >= '0' && znak <= '9' || znak == '-' || znak == '_' || znak == '.' {
			continue
		}
		return fmt.Errorf("identyfikator zlecenia %q zawiera niedozwolony znak", zlecenie)
	}
	return nil
}

// ParsujGetcert czyta wyjscie "getcert list".
//
// Wpisy sa blokami "Request ID 'nazwa':" z wcieciami. Interesuja nas cztery
// rzeczy: gdzie lezy certyfikat, gdzie klucz, w jakim stanie jest zlecenie
// i czy demon odnowi je sam. Wynik jest mapowany po sciezce certyfikatu, bo
// to ona laczy zlecenie z plikiem, ktory widzi panel.
func ParsujGetcert(wyjscie string) map[string]Sledzenie {
	sledzenia := map[string]Sledzenie{}
	var biezace Sledzenie
	var sciezka string

	zapisz := func() {
		if sciezka != "" {
			sledzenia[sciezka] = biezace
		}
		biezace, sciezka = Sledzenie{}, ""
	}

	for _, linia := range strings.Split(wyjscie, "\n") {
		przyciete := strings.TrimSpace(linia)
		switch {
		case strings.HasPrefix(przyciete, "Request ID"):
			zapisz()
			biezace.Request = strings.Trim(strings.TrimSpace(
				strings.TrimSuffix(strings.TrimPrefix(przyciete, "Request ID"), ":")), "'")
		case strings.HasPrefix(przyciete, "status:"):
			biezace.Status = strings.TrimSpace(strings.TrimPrefix(przyciete, "status:"))
		case strings.HasPrefix(przyciete, "CA:"):
			biezace.CA = strings.TrimSpace(strings.TrimPrefix(przyciete, "CA:"))
		case strings.HasPrefix(przyciete, "certificate:"):
			sciezka = sciezkaZLokalizacji(strings.TrimPrefix(przyciete, "certificate:"))
		case strings.HasPrefix(przyciete, "key pair storage:"):
			biezace.KeyPath = sciezkaZLokalizacji(strings.TrimPrefix(przyciete, "key pair storage:"))
		case strings.HasPrefix(przyciete, "auto-renew:"):
			wartosc := strings.TrimSpace(strings.TrimPrefix(przyciete, "auto-renew:")) == "yes"
			biezace.AutoRenew = &wartosc
		case strings.HasPrefix(przyciete, "expires:"):
			if chwila, ok := ParsujTerminGetcert(strings.TrimPrefix(przyciete, "expires:")); ok {
				biezace.Expires = &chwila
			}
		}
	}
	zapisz()
	return sledzenia
}

// sciezkaZLokalizacji wyciaga sciezke z opisu "type=FILE,location='/sciezka'".
func sciezkaZLokalizacji(opis string) string {
	for _, pole := range strings.Split(strings.TrimSpace(opis), ",") {
		klucz, wartosc, ok := strings.Cut(pole, "=")
		if !ok || strings.TrimSpace(klucz) != "location" {
			continue
		}
		return strings.Trim(strings.TrimSpace(wartosc), "'\"")
	}
	return ""
}

// ParsujTerminGetcert czyta date w formacie, ktorym odpowiada certmonger.
func ParsujTerminGetcert(wartosc string) (time.Time, bool) {
	wartosc = strings.TrimSpace(wartosc)
	for _, uklad := range []string{
		"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05", time.RFC3339,
	} {
		if chwila, err := time.Parse(uklad, wartosc); err == nil {
			return chwila.UTC(), true
		}
	}
	return time.Time{}, false
}
