// Package enrollment realizuje przyjmowanie nowych hostow do floty.
//
// Zamowienie enrollmentu jest trwalym rekordem oczekujacej instalacji: kto ja
// zamowil, w jakim celu, w jakim zakresie i czym sie skonczyla. Token jest
// tylko sekretem, ktory autoryzuje jedna probe - jego jawna wartosc istnieje
// wylacznie w odpowiedzi na utworzenie zamowienia, a w bazie zostaje sam skrot.
//
// Cel zamowienia jest tu najwazniejszym polem. "Nowy host" i "wymiana
// tozsamosci istniejacego hosta" to dwie rozne decyzje: bez tego rozroznienia
// ktokolwiek z tokenem moglby cicho przejac tozsamosc dzialajacej maszyny.
package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenPrefix odroznia token enrollmentu od innych sekretow w logach i configach.
const TokenPrefix = "flt_"

// ErrInvalidToken jest zwracany dla kazdego powodu odrzucenia tokenu, aby nie
// ujawniac, czy token istnieje, wygasl, czy wyczerpal limit uzyc.
var ErrInvalidToken = errors.New("token enrollmentu jest nieprawidlowy")

// ErrNieznaneZamowienie oznacza zamowienie, ktorego nie ma.
var ErrNieznaneZamowienie = errors.New("zamowienie enrollmentu nie istnieje")

// Rodzaje tozsamosci, ktore mozna zarejestrowac.
const (
	KindAgent = "agent"
	KindRelay = "relay"
)

// Cele zamowienia.
const (
	// CelNowy przyjmuje maszyne, ktorej panel jeszcze nie zna.
	CelNowy = "new"
	// CelWymiana odtwarza tozsamosc istniejacego hosta - po przeinstalowaniu
	// albo po utracie klucza. Zawsze wskazuje konkretny host.
	CelWymiana = "replace_identity"
	// CelRelay rejestruje relay lokalizacji.
	CelRelay = "relay"
)

// Statusy zamowienia. Sa dla operatora i audytu, nigdy podstawa autoryzacji -
// o tym rozstrzyga wylacznie stan tokenu sprawdzany w transakcji.
const (
	StatusOczekuje       = "pending"
	StatusZarejestrowany = "enrolled"
	StatusWygasl         = "expired"
	StatusUniewazniony   = "revoked"
	StatusNieudany       = "failed"
)

// MaksymalnyTTL ogranicza czas zycia zamowienia.
//
// Token, ktory lezy tygodniami, jest sekretem czekajacym na wyciek. Dluzsze
// automatyzacje maja pobierac krotkie tokeny na zadanie, a nie trzymac jeden
// na zapas.
const MaksymalnyTTL = 24 * time.Hour

// Zamowienie opisuje oczekujaca instalacje.
type Zamowienie struct {
	ID string `json:"id"`
	// Value jest jawnym tokenem i pojawia sie wylacznie w odpowiedzi na
	// utworzenie zamowienia. Nigdzie indziej - ani w liscie, ani w audycie.
	Value       string `json:"token,omitempty"`
	Description string `json:"description,omitempty"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Kind        string `json:"kind"`
	Purpose     string `json:"purpose"`
	// ExpectedMachineID i ExpectedHostID zawezaja zamowienie do konkretnej
	// maszyny i konkretnego hosta.
	ExpectedMachineID string `json:"expected_machine_id,omitempty"`
	ExpectedHostID    string `json:"expected_host_id,omitempty"`
	// RelayID ogranicza trase zgloszenia do jednego relaya.
	RelayID        string `json:"relay_id,omitempty"`
	MaxUses        int    `json:"max_uses"`
	Uses           int    `json:"uses"`
	Status         string `json:"status"`
	EnrolledHostID string `json:"enrolled_host_id,omitempty"`

	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Scope to zakres, w ktorym zamowienie pozwala zarejestrowac tozsamosc.
type Scope struct {
	// TokenID jest identyfikatorem zamowienia. Nazwa zostaje ze wzgledu na
	// audyt, ktory zapisuje ja od poczatku istnienia floty.
	TokenID           string
	Site              string
	Environment       string
	Kind              string
	Purpose           string
	ExpectedMachineID string
	ExpectedHostID    string
	// RelayID ogranicza trase zgloszenia. Puste znaczy "dowolna": token
	// zwiazany z relayem nie zadziala poza jego lokalizacja, a token bez
	// zwiazku dziala tak jak dotad.
	RelayID string
}

// Powtorzenie jest zapisem proby, ktora juz sie udala.
//
// Odpowiedz moze zginac w sieci po tym, jak serwer zapisal hosta i wystawil
// certyfikat. Wtedy agent ponawia probe i musi dostac to samo, co juz zostalo
// wydane - inaczej token jest zuzyty, a host zostaje bez tozsamosci.
type Powtorzenie struct {
	HostID            string
	CertificatePEM    []byte
	CABundlePEM       []byte
	CertificateSerial string
}

// ProbaWejscie opisuje jedna probe enrollmentu.
type ProbaWejscie struct {
	Token           string
	MachineID       string
	ClientRequestID string
	CSR             []byte
}

// Wynik mowi, co zrobic z proba: wydac nowa tozsamosc albo powtorzyc stara.
type Wynik struct {
	Scope       Scope
	Powtorzenie *Powtorzenie
}

// Store zarzadza zamowieniami enrollmentu.
type Store struct {
	pool *pgxpool.Pool
}

// NewTokenStore tworzy magazyn zamowien.
func NewTokenStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// TworzenieWejscie opisuje nowe zamowienie.
type TworzenieWejscie struct {
	Description       string
	Site              string
	Environment       string
	Kind              string
	Purpose           string
	ExpectedMachineID string
	ExpectedHostID    string
	// RelayID zamyka zamowienie w jednej lokalizacji. Token wyniesiony poza
	// nia nie zarejestruje niczego: centrala sprawdza, ktory relay podpisal
	// zgloszenie swoim kanalem mTLS.
	RelayID   string
	MaxUses   int
	TTL       time.Duration
	CreatedBy string
}

// Create wystawia nowe zamowienie. W bazie zapisywany jest wylacznie skrot.
func (s *Store) Create(ctx context.Context, wejscie TworzenieWejscie) (*Zamowienie, error) {
	kind := wejscie.Kind
	if kind == "" {
		kind = KindAgent
	}
	if kind != KindAgent && kind != KindRelay {
		return nil, fmt.Errorf("nieznany rodzaj tozsamosci %q", kind)
	}
	purpose := wejscie.Purpose
	if purpose == "" {
		if kind == KindRelay {
			purpose = CelRelay
		} else {
			purpose = CelNowy
		}
	}
	if err := sprawdzCel(kind, purpose, wejscie.ExpectedHostID); err != nil {
		return nil, err
	}

	maxUses := wejscie.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	// Wymiana tozsamosci dotyczy jednego hosta, wiec i jednego uzycia:
	// zamowienie wielokrotne bylo by kluczem do tej samej maszyny na zapas.
	if purpose == CelWymiana {
		maxUses = 1
	}
	ttl := wejscie.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > MaksymalnyTTL {
		return nil, fmt.Errorf("czas zycia zamowienia przekracza %s", MaksymalnyTTL)
	}

	surowy := make([]byte, 32)
	if _, err := rand.Read(surowy); err != nil {
		return nil, err
	}
	value := TokenPrefix + base64.RawURLEncoding.EncodeToString(surowy)
	hash := hashToken(value)

	zamowienie := &Zamowienie{
		ID: uuid.NewString(), Value: value, Description: wejscie.Description,
		Site: wejscie.Site, Environment: wejscie.Environment,
		Kind: kind, Purpose: purpose,
		ExpectedMachineID: wejscie.ExpectedMachineID, ExpectedHostID: wejscie.ExpectedHostID,
		RelayID: wejscie.RelayID,
		MaxUses: maxUses, Status: StatusOczekuje,
		ExpiresAt: time.Now().Add(ttl), CreatedBy: wejscie.CreatedBy,
	}
	const query = `
		insert into enrollment_requests
			(id, token_hash, description, site, environment, kind, purpose,
			 expected_machine_id, expected_host_id, relay_id, max_uses, expires_at, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid, nullif($10, '')::uuid, $11, $12, $13)
		returning created_at, updated_at`
	err := s.pool.QueryRow(ctx, query, zamowienie.ID, hash[:], nullable(wejscie.Description),
		wejscie.Site, wejscie.Environment, kind, purpose,
		nullable(wejscie.ExpectedMachineID), nullable(wejscie.ExpectedHostID),
		wejscie.RelayID, maxUses, zamowienie.ExpiresAt, wejscie.CreatedBy).
		Scan(&zamowienie.CreatedAt, &zamowienie.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("zapis zamowienia: %w", err)
	}
	return zamowienie, nil
}

// sprawdzCel pilnuje, ze cel, rodzaj i wskazany host trzymaja sie razem.
func sprawdzCel(kind, purpose, hostID string) error {
	switch purpose {
	case CelNowy:
		if kind != KindAgent {
			return fmt.Errorf("cel %q wymaga rodzaju %q", purpose, KindAgent)
		}
		if hostID != "" {
			return fmt.Errorf("cel %q nie wskazuje istniejacego hosta", purpose)
		}
	case CelWymiana:
		if kind != KindAgent {
			return fmt.Errorf("cel %q wymaga rodzaju %q", purpose, KindAgent)
		}
		if hostID == "" {
			return fmt.Errorf("cel %q wymaga wskazania hosta", purpose)
		}
	case CelRelay:
		if kind != KindRelay {
			return fmt.Errorf("cel %q wymaga rodzaju %q", purpose, KindRelay)
		}
		if hostID != "" {
			return fmt.Errorf("cel %q nie wskazuje hosta", purpose)
		}
	default:
		return fmt.Errorf("nieznany cel zamowienia %q", purpose)
	}
	return nil
}

// Redeem sprawdza token i rozstrzyga, czy to nowa proba, czy powtorzenie.
//
// Wiersz jest blokowany, wiec rownolegly enrollment nie przekroczy limitu
// uzyc. Powtorzenie nie zuzywa uzycia: to ta sama proba, ktorej odpowiedz
// zginela.
func (s *Store) Redeem(ctx context.Context, tx pgx.Tx, wejscie ProbaWejscie) (Wynik, error) {
	value := strings.TrimSpace(wejscie.Token)
	if value == "" {
		return Wynik{}, ErrInvalidToken
	}
	hash := hashToken(value)

	const query = `
		select id, site, environment, kind, purpose,
		       coalesce(expected_machine_id, ''), coalesce(expected_host_id::text, ''),
		       coalesce(relay_id::text, ''),
		       max_uses, uses, expires_at, revoked_at
		from enrollment_requests
		where token_hash = $1
		for update`
	var (
		scope     Scope
		maxUses   int
		uses      int
		expiresAt time.Time
		revokedAt *time.Time
	)
	err := tx.QueryRow(ctx, query, hash[:]).
		Scan(&scope.TokenID, &scope.Site, &scope.Environment, &scope.Kind, &scope.Purpose,
			&scope.ExpectedMachineID, &scope.ExpectedHostID, &scope.RelayID,
			&maxUses, &uses, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Wynik{}, ErrInvalidToken
	}
	if err != nil {
		return Wynik{}, err
	}

	// Powtorzenie sprawdzamy przed limitami: proba, ktora juz sie udala, ma
	// dostac swoja odpowiedz takze wtedy, gdy zamowienie zdazylo sie wyczerpac.
	powtorzenie, err := s.powtorzenie(ctx, tx, scope.TokenID, wejscie)
	if err != nil {
		return Wynik{}, err
	}
	if powtorzenie != nil {
		return Wynik{Scope: scope, Powtorzenie: powtorzenie}, nil
	}

	switch {
	case revokedAt != nil:
		return Wynik{}, ErrInvalidToken
	case time.Now().After(expiresAt):
		return Wynik{}, ErrInvalidToken
	case uses >= maxUses:
		return Wynik{}, ErrInvalidToken
	}
	// Zamowienie zwiazane z maszyna nie pasuje do zadnej innej.
	if scope.ExpectedMachineID != "" && scope.ExpectedMachineID != wejscie.MachineID {
		return Wynik{}, ErrInvalidToken
	}

	if _, err := tx.Exec(ctx,
		`update enrollment_requests set uses = uses + 1, updated_at = now() where id = $1::uuid`,
		scope.TokenID); err != nil {
		return Wynik{}, err
	}
	return Wynik{Scope: scope}, nil
}

// powtorzenie szuka proby, ktora juz sie udala.
//
// Szukamy po identyfikatorze proby i po odcisku CSR: agent, ktory zgubil
// odpowiedz i ponawia z nowym identyfikatorem, ale tym samym kluczem, pyta
// o dokladnie te sama tozsamosc.
func (s *Store) powtorzenie(ctx context.Context, tx pgx.Tx, requestID string,
	wejscie ProbaWejscie) (*Powtorzenie, error) {
	odcisk := sha256.Sum256(wejscie.CSR)
	const query = `
		select coalesce(host_id::text, ''), certificate_pem, ca_bundle_pem,
		       coalesce(certificate_serial, ''), csr_sha256
		from enrollment_attempts
		where request_id = $1::uuid and (client_request_id = $2::uuid or csr_sha256 = $3)
		  and completed_at is not null
		limit 1`
	klient := wejscie.ClientRequestID
	if klient == "" {
		// Agent bez identyfikatora proby moze byc rozpoznany tylko po CSR.
		klient = uuid.Nil.String()
	}
	var (
		hostID      string
		certPEM     []byte
		bundlePEM   []byte
		serial      string
		zapisanyCSR []byte
	)
	err := tx.QueryRow(ctx, query, requestID, klient, odcisk[:]).
		Scan(&hostID, &certPEM, &bundlePEM, &serial, &zapisanyCSR)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Ten sam identyfikator proby z innym CSR to nie jest powtorzenie, tylko
	// inna proba pod cudzym numerem. Odmawiamy, zamiast wydawac tozsamosc.
	if !bytes.Equal(zapisanyCSR, odcisk[:]) {
		return nil, ErrInvalidToken
	}
	return &Powtorzenie{
		HostID: hostID, CertificatePEM: certPEM,
		CABundlePEM: bundlePEM, CertificateSerial: serial,
	}, nil
}

// ZapiszProbe utrwala udana probe razem z wydanym certyfikatem.
//
// W tej samej transakcji, w ktorej powstaje host i certyfikat: zapis proby po
// commicie moglby nie dojsc do skutku i cala idempotencja bylaby pozorna.
func (s *Store) ZapiszProbe(ctx context.Context, tx pgx.Tx, requestID string,
	wejscie ProbaWejscie, wynik Powtorzenie) error {
	odcisk := sha256.Sum256(wejscie.CSR)
	klient := wejscie.ClientRequestID
	if klient == "" {
		klient = uuid.NewString()
	}
	const query = `
		insert into enrollment_attempts
			(request_id, client_request_id, csr_sha256, machine_id, host_id,
			 certificate_pem, ca_bundle_pem, certificate_serial, completed_at)
		values ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, now())
		on conflict (request_id, client_request_id) do update set
			host_id = excluded.host_id, certificate_pem = excluded.certificate_pem,
			ca_bundle_pem = excluded.ca_bundle_pem,
			certificate_serial = excluded.certificate_serial, completed_at = now()`
	if _, err := tx.Exec(ctx, query, requestID, klient, odcisk[:], wejscie.MachineID,
		nullable(wynik.HostID), wynik.CertificatePEM, wynik.CABundlePEM,
		nullable(wynik.CertificateSerial)); err != nil {
		return fmt.Errorf("zapis proby enrollmentu: %w", err)
	}

	const domkniecie = `
		update enrollment_requests
		set enrolled_host_id = coalesce($2::uuid, enrolled_host_id),
		    status = case when uses >= max_uses then $3 else status end,
		    updated_at = now()
		where id = $1::uuid`
	if _, err := tx.Exec(ctx, domkniecie, requestID, nullable(wynik.HostID),
		StatusZarejestrowany); err != nil {
		return fmt.Errorf("domkniecie zamowienia: %w", err)
	}
	return nil
}

// Uniewaznij blokuje pozostale uzycia zamowienia.
//
// Dziala takze wtedy, gdy czesc puli zostala juz wykorzystana: cofniecie ma
// zamknac to, co zostalo, a nie udawac, ze nic sie nie stalo.
func (s *Store) Uniewaznij(ctx context.Context, id string) error {
	const query = `
		update enrollment_requests
		set revoked_at = coalesce(revoked_at, now()),
		    status = $2, updated_at = now()
		where id = $1::uuid`
	znacznik, err := s.pool.Exec(ctx, query, id, StatusUniewazniony)
	if err != nil {
		return err
	}
	if znacznik.RowsAffected() == 0 {
		return ErrNieznaneZamowienie
	}
	return nil
}

// Zamowienie zwraca jedno zamowienie bez wartosci tokenu.
func (s *Store) Zamowienie(ctx context.Context, id string) (*Zamowienie, error) {
	const query = kolumnyZamowienia + ` where id = $1::uuid`
	wiersz := s.pool.QueryRow(ctx, query, id)
	zamowienie, err := skanujZamowienie(wiersz)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNieznaneZamowienie
	}
	if err != nil {
		return nil, err
	}
	return zamowienie, nil
}

// List zwraca zamowienia bez wartosci jawnej.
//
// Takze zamkniete i cofniete: operator musi widziec, co sie stalo z instalacja,
// ktora zamowil, a nie tylko to, co jeszcze czeka.
func (s *Store) List(ctx context.Context) ([]Zamowienie, error) {
	const query = kolumnyZamowienia + ` order by created_at desc limit 200`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var zamowienia []Zamowienie
	for rows.Next() {
		zamowienie, err := skanujZamowienie(rows)
		if err != nil {
			return nil, err
		}
		zamowienia = append(zamowienia, *zamowienie)
	}
	return zamowienia, rows.Err()
}

// kolumnyZamowienia jest wspolna lista kolumn odczytu.
const kolumnyZamowienia = `
	select id, coalesce(description, ''), site, environment, kind, purpose,
	       coalesce(expected_machine_id, ''), coalesce(expected_host_id::text, ''),
	       coalesce(relay_id::text, ''),
	       max_uses, uses, status, coalesce(enrolled_host_id::text, ''),
	       expires_at, revoked_at, created_by, created_at, updated_at
	from enrollment_requests`

// skaner pozwala czytac zamowienie z wiersza i z kursora.
type skaner interface {
	Scan(cele ...any) error
}

func skanujZamowienie(wiersz skaner) (*Zamowienie, error) {
	var z Zamowienie
	if err := wiersz.Scan(&z.ID, &z.Description, &z.Site, &z.Environment, &z.Kind, &z.Purpose,
		&z.ExpectedMachineID, &z.ExpectedHostID, &z.RelayID, &z.MaxUses, &z.Uses, &z.Status,
		&z.EnrolledHostID, &z.ExpiresAt, &z.RevokedAt, &z.CreatedBy,
		&z.CreatedAt, &z.UpdatedAt); err != nil {
		return nil, err
	}
	// Status "pending" po terminie jest nieprawda: token juz nie dziala.
	if z.Status == StatusOczekuje && time.Now().After(z.ExpiresAt) {
		z.Status = StatusWygasl
	}
	return &z, nil
}

func hashToken(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
