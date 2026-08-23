// Package hosts przechowuje tozsamosc i stan hostow. Pakiet nie zna warstwy
// HTTP ani protokolu agenta; mapowanie kontraktow nalezy do gatewaya.
package hosts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound oznacza brak hosta o podanej tozsamosci.
var ErrNotFound = errors.New("host nie istnieje")

// Capability opisuje jeden adapter wykryty na hoscie. Nazwa mowi, co host ma
// ('packages.apt'), a nie czego chce operacja ('packages').
type Capability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason,omitempty"`
	Features  map[string]bool `json:"features,omitempty"`
}

// Capabilities to rejestr adapterow hosta.
type Capabilities []Capability

// Nazwy adapterow oraz wymagania operacji. Wymaganie jest nazwa logiczna:
// operacja aktualizacji nie ma wiedziec, czy host uzywa apta czy dnf-a.
const (
	CapSystemd   = "systemd"
	CapAPT       = "packages.apt"
	CapDNF       = "packages.dnf"
	CapJournald  = "journald"
	CapDocker    = "docker"
	CapCompose   = "docker.compose"
	CapSchedules = "schedules"
	CapNetwork   = "network"
	CapDNS       = "dns"
	CapFirewall  = "firewall"
	CapStorage   = "storage"

	WymaganiePakiety         = "packages"
	WymaganieNaprawaPakietow = "packages.repair"
	// Zapis konfiguracji sieci. Odczyt dziala wszedzie, gdzie jest iproute2,
	// wiec sam modul nie mowi jeszcze, ze da sie tu cokolwiek zmienic.
	WymaganieZapisSieci  = "network.write"
	WymaganieZapisDNS    = "dns.write"
	WymaganieZapisZapory = "firewall.write"
	WymaganieStrefZapory = "firewall.zones"
	WymaganieLVM         = "storage.lvm"
)

// Available mowi, czy adapter o tej nazwie dziala na hoscie.
func (c Capabilities) Available(name string) bool {
	for _, capability := range c {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}

// Feature mowi, czy adapter ma dana czesc.
func (c Capabilities) Feature(name, feature string) bool {
	wartosc, _ := c.FeatureStan(name, feature)
	return wartosc
}

// FeatureStan oddziela "nie ma tej czesci" od "nie wiadomo, czy ma".
//
// Agent sprzed rejestru nie przysyla cech wcale, a jego rejestr jest
// odtwarzany z pol logicznych. Uznanie milczenia za odmowe odebraloby takiemu
// hostowi operacje, ktora u niego dziala - nieznana cecha nie jest cecha
// nieobecna.
func (c Capabilities) FeatureStan(name, feature string) (wartosc bool, znana bool) {
	for _, capability := range c {
		if capability.Name != name {
			continue
		}
		if !capability.Available {
			// Adapter, ktorego nie ma, na pewno nie ma zadnej czesci.
			return false, true
		}
		value, ok := capability.Features[feature]
		return value, ok
	}
	// Adaptera nie ma w rejestrze - to tez jest odpowiedz, a nie niewiedza.
	return false, true
}

// Reason zwraca wyjasnienie zapisane przez hosta. Interfejs ma powtarzac to,
// co powiedzial host, a nie zgadywac przyczyne w kodzie przegladarki.
func (c Capabilities) Reason(name string) string {
	for _, capability := range c {
		if capability.Name == name {
			return capability.Reason
		}
	}
	return ""
}

// Spelnia sprawdza wymaganie operacji wobec rejestru hosta.
func (c Capabilities) Spelnia(wymaganie string) bool {
	switch wymaganie {
	case "":
		return true
	case WymaganiePakiety:
		return c.Available(CapAPT) || c.Available(CapDNF)
	case WymaganieNaprawaPakietow:
		for _, adapter := range []string{CapAPT, CapDNF} {
			wartosc, znana := c.FeatureStan(adapter, "repair")
			if wartosc {
				return true
			}
			// Adapter obecny, ale milczacy o cechach: decyzje podejmuje host
			// przy wykonaniu, tak jak przed wprowadzeniem rejestru.
			if !znana && c.Available(adapter) {
				return true
			}
		}
		return false
	case WymaganieZapisZapory:
		wartosc, znana := c.FeatureStan(CapFirewall, "write")
		if wartosc {
			return true
		}
		return !znana && c.Available(CapFirewall)
	case WymaganieLVM:
		// Rozszerzenie wolumenu ma sens tylko tam, gdzie LVM w ogole jest.
		wartosc, _ := c.FeatureStan(CapStorage, "lvm")
		return wartosc
	case WymaganieStrefZapory:
		wartosc, _ := c.FeatureStan(CapFirewall, "zones")
		return wartosc
	case WymaganieZapisDNS:
		wartosc, znana := c.FeatureStan(CapDNS, "write")
		if wartosc {
			return true
		}
		return !znana && c.Available(CapDNS)
	case WymaganieZapisSieci:
		// Zapis sieci wymaga mechanizmu, ktory utrwali zmiane i pozwoli ja
		// wycofac. Host bez niego ma sie o tym dowiedziec przy zlecaniu,
		// a nie po dostarczeniu zadania.
		wartosc, znana := c.FeatureStan(CapNetwork, "write")
		if wartosc {
			return true
		}
		// Adapter obecny, ale milczacy o cechach: decyzje podejmuje host
		// przy wykonaniu, tak jak przed wprowadzeniem rejestru.
		return !znana && c.Available(CapNetwork)
	default:
		return c.Available(wymaganie)
	}
}

// Health to minimalny zestaw sygnalow z heartbeatu. Wskaznik pusty oznacza
// stan nieustalony przez agenta i nie nadpisuje ostatniej znanej wartosci.
type Health struct {
	FailedUnits            *uint32
	RebootRequired         *bool
	Load1Milli             uint32
	RootFSUsedPercent      uint32
	UptimeSeconds          uint64
	PendingUpdates         *uint32
	PendingSecurityUpdates *uint32
}

// Identity to dane zgloszone przy enrollmencie.
type Identity struct {
	MachineID    string
	Hostname     string
	Site         string
	Environment  string
	OSFamily     string
	OSVersion    string
	Architecture string
	AgentVersion string
}

// Host jest widokiem hosta zwracanym przez API.
type Host struct {
	ID              string     `json:"id"`
	MachineID       string     `json:"machine_id"`
	Hostname        string     `json:"hostname"`
	Site            string     `json:"site"`
	Environment     string     `json:"environment"`
	Owner           string     `json:"owner,omitempty"`
	LifecycleState  string     `json:"lifecycle_state"`
	OSFamily        string     `json:"os_family,omitempty"`
	OSDistribution  string     `json:"os_distribution,omitempty"`
	OSVersion       string     `json:"os_version,omitempty"`
	Architecture    string     `json:"architecture,omitempty"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	ConnectionState string     `json:"connection_state"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	BootID          string     `json:"boot_id,omitempty"`
	// Puste pola oznaczaja stan nieustalony, nie zero.
	RebootRequired           *bool  `json:"reboot_required"`
	FailedUnits              *int   `json:"failed_units"`
	PendingUpdates           *int   `json:"pending_updates"`
	PendingSecurityUpdates   *int   `json:"pending_security_updates"`
	CurrentInventoryRevision string `json:"current_inventory_revision,omitempty"`
	PackageDatabaseBroken    bool   `json:"package_database_broken"`
	// Adres zarzadzania i jego pochodzenie. Puste pola oznaczaja adres
	// nieustalony; interfejs ma wtedy powiedziec "unknown", a nie pokazac
	// dowolny adres hosta jako rzekomy adres zarzadzania.
	ManagementAddress           string       `json:"management_address,omitempty"`
	ManagementAddressSource     string       `json:"management_address_source,omitempty"`
	ManagementAddressObservedAt *time.Time   `json:"management_address_observed_at,omitempty"`
	Identity                    HostIdentity `json:"identity"`
	EnrolledAt                  time.Time    `json:"enrolled_at"`
	Capabilities                Capabilities `json:"capabilities"`
}

// HostIdentity opisuje integracje hosta z domena w widoku API.
type HostIdentity struct {
	Enrolled   bool       `json:"enrolled"`
	Domain     string     `json:"domain,omitempty"`
	Realm      string     `json:"realm,omitempty"`
	SSSDOnline *bool      `json:"sssd_online"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

// Store realizuje dostep do tabel hostow.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Upsert tworzy host lub aktualizuje jego dane identyfikacyjne.
// Kluczem tozsamosci jest machine_id, dzieki czemu ponowny enrollment tej samej
// maszyny nie tworzy duplikatu.
func (s *Store) Upsert(ctx context.Context, tx pgx.Tx, id Identity) (hostID string, created bool, err error) {
	const query = `
		insert into hosts (id, machine_id, hostname, site, environment,
		                   os_family, os_version, architecture, agent_version)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		on conflict (machine_id) do update set
			hostname      = excluded.hostname,
			os_family     = coalesce(nullif(excluded.os_family, ''), hosts.os_family),
			os_version    = coalesce(nullif(excluded.os_version, ''), hosts.os_version),
			architecture  = coalesce(nullif(excluded.architecture, ''), hosts.architecture),
			agent_version = coalesce(nullif(excluded.agent_version, ''), hosts.agent_version),
			updated_at    = now()
		returning id, (xmax = 0) as created`
	newID := uuid.NewString()
	err = tx.QueryRow(ctx, query, newID, id.MachineID, id.Hostname, id.Site, id.Environment,
		id.OSFamily, id.OSVersion, id.Architecture, id.AgentVersion).Scan(&hostID, &created)
	if err != nil {
		return "", false, fmt.Errorf("upsert hosta: %w", err)
	}
	return hostID, created, nil
}

// SaveCertificate zapisuje wystawiony certyfikat agenta.
func (s *Store) SaveCertificate(ctx context.Context, tx pgx.Tx, hostID, serial, commonName string,
	fingerprint []byte, notBefore, notAfter time.Time, issuerSubject, issuerSerial string) error {
	const query = `
		insert into agent_certificates
			(id, host_id, serial, fingerprint_sha256, subject_common_name, not_before, not_after,
			 issuer_subject, issuer_serial)
		values ($1, $2, $3, $4, $5, $6, $7, nullif($8, ''), nullif($9, ''))`
	_, err := tx.Exec(ctx, query, uuid.NewString(), hostID, serial, fingerprint, commonName,
		notBefore, notAfter, issuerSubject, issuerSerial)
	if err != nil {
		return fmt.Errorf("zapis certyfikatu: %w", err)
	}
	return nil
}

// CertificateStatus opisuje stan certyfikatu przedstawionego przez agenta.
type CertificateStatus struct {
	HostID         string
	LifecycleState string
	Revoked        bool
	Known          bool
	// Serial identyfikuje certyfikat w sladzie audytowym; przy odnowieniu
	// pozwala powiazac nowy certyfikat z zastapionym.
	Serial string
}

// LookupCertificate sprawdza, czy certyfikat jest znany i nieodwolany oraz czy
// host nie jest w kwarantannie. Gateway odrzuca sesje na podstawie tego wyniku.
func (s *Store) LookupCertificate(ctx context.Context, fingerprint []byte) (CertificateStatus, error) {
	const query = `
		select c.host_id, h.lifecycle_state, c.revoked_at is not null, c.serial
		from agent_certificates c
		join hosts h on h.id = c.host_id
		where c.fingerprint_sha256 = $1`
	var status CertificateStatus
	err := s.pool.QueryRow(ctx, query, fingerprint).
		Scan(&status.HostID, &status.LifecycleState, &status.Revoked, &status.Serial)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateStatus{}, nil
	}
	if err != nil {
		return CertificateStatus{}, err
	}
	status.Known = true
	return status, nil
}

// ApplyHello zapisuje dane sesji zgloszone w pierwszej wiadomosci streamu.
func (s *Store) ApplyHello(ctx context.Context, hostID, agentVersion, bootID string, caps Capabilities) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const hostQuery = `
		update hosts set
			agent_version    = coalesce(nullif($2, ''), agent_version),
			boot_id          = coalesce(nullif($3, ''), boot_id),
			connection_state = 'online',
			last_seen_at     = now(),
			updated_at       = now()
		where id = $1`
	if _, err := tx.Exec(ctx, hostQuery, hostID, agentVersion, bootID); err != nil {
		return fmt.Errorf("aktualizacja hosta: %w", err)
	}

	// Rejestr jest zastepowany w calosci: adapter, ktorego host juz nie zglasza,
	// zniknal z hosta i nie moze zostac w bazie jako nieaktualna prawda.
	const usunQuery = `delete from host_capability_registry where host_id = $1`
	if _, err := tx.Exec(ctx, usunQuery, hostID); err != nil {
		return fmt.Errorf("czyszczenie rejestru adapterow: %w", err)
	}
	const capQuery = `
		insert into host_capability_registry
			(host_id, name, version, available, read_only, reason, features, observed_at)
		values ($1, $2, $3, $4, $5, nullif($6, ''), $7, now())`
	for _, capability := range caps {
		features, err := json.Marshal(capability.Features)
		if err != nil {
			return err
		}
		if capability.Features == nil {
			features = []byte("{}")
		}
		if _, err := tx.Exec(ctx, capQuery, hostID, capability.Name,
			capability.Version, capability.Available, capability.ReadOnly,
			capability.Reason, features); err != nil {
			return fmt.Errorf("aktualizacja adaptera %s: %w", capability.Name, err)
		}
	}
	return tx.Commit(ctx)
}

// ApplyHeartbeat zapisuje minimalne sygnaly zdrowia i odswieza last_seen_at.
// Sygnal nieustalony przez agenta zostawia poprzednia wartosc nietknieta:
// chwilowa awaria odczytu na hoscie nie moze kasowac tego, co juz wiemy, ani
// udawac zera.
func (s *Store) ApplyHeartbeat(ctx context.Context, hostID string, health Health) error {
	const query = `
		update hosts set
			failed_units             = coalesce($2, failed_units),
			reboot_required          = coalesce($3, reboot_required),
			pending_updates          = coalesce($4, pending_updates),
			pending_security_updates = coalesce($5, pending_security_updates),
			connection_state         = 'online',
			last_seen_at             = now(),
			updated_at               = now()
		where id = $1`
	_, err := s.pool.Exec(ctx, query, hostID,
		countArg(health.FailedUnits), health.RebootRequired,
		countArg(health.PendingUpdates), countArg(health.PendingSecurityUpdates))
	return err
}

// countArg zamienia nieustalony licznik na NULL dla zapytania.
func countArg(value *uint32) any {
	if value == nil {
		return nil
	}
	return int(*value)
}

// SetPackageDatabaseBroken zapisuje, czy baza pakietow hosta wymaga naprawy.
// Host w tym stanie nie moze brac udzialu w kolejnych kampaniach.
func (s *Store) SetPackageDatabaseBroken(ctx context.Context, hostID string, broken bool) error {
	const query = `update hosts set package_database_broken = $2, updated_at = now() where id = $1`
	_, err := s.pool.Exec(ctx, query, hostID, broken)
	return err
}

// MarkDisconnected oznacza hosta jako offline po zamknieciu streamu.
func (s *Store) MarkDisconnected(ctx context.Context, hostID string) error {
	const query = `update hosts set connection_state = 'offline', updated_at = now() where id = $1`
	_, err := s.pool.Exec(ctx, query, hostID)
	return err
}

// Get zwraca pojedynczy host.
func (s *Store) Get(ctx context.Context, hostID string) (*Host, error) {
	rows, err := s.query(ctx, "where h.id = $1", hostID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return &rows[0], nil
}

// ListFilter opisuje filtry wykonywane po stronie serwera.
type ListFilter struct {
	Site            string
	Environment     string
	OSFamily        string
	ConnectionState string
	// IdentityDomain zaweza do hostow w danej domenie.
	IdentityDomain string
	Limit          int
}

// List zwraca hosty zgodne z filtrem. Filtrowanie odbywa sie w bazie, UI nigdy
// nie pobiera calej floty do pamieci przegladarki.
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Host, error) {
	var (
		conditions []string
		args       []any
	)
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	add("h.site", filter.Site)
	add("h.environment", filter.Environment)
	add("h.os_family", filter.OSFamily)
	add("h.connection_state", filter.ConnectionState)
	add("h.identity_domain", filter.IdentityDomain)

	where := ""
	if len(conditions) > 0 {
		where = "where " + strings.Join(conditions, " and ")
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	where += fmt.Sprintf(" order by h.hostname limit $%d", len(args))

	return s.query(ctx, where, args...)
}

func (s *Store) query(ctx context.Context, clause string, args ...any) ([]Host, error) {
	query := `
		select h.id, h.machine_id, h.hostname, h.site, h.environment, coalesce(h.owner, ''),
		       h.lifecycle_state, coalesce(h.os_family, ''), coalesce(h.os_distribution, ''),
		       coalesce(h.os_version, ''), coalesce(h.architecture, ''), coalesce(h.agent_version, ''),
		       h.connection_state, h.last_seen_at, coalesce(h.boot_id, ''),
		       h.reboot_required, h.failed_units, h.pending_updates, h.pending_security_updates,
		       coalesce(h.current_inventory_revision, ''), h.package_database_broken, h.enrolled_at,
		       coalesce(h.management_address, ''), coalesce(h.management_address_source, ''),
		       h.management_address_observed_at,
		       h.identity_enrolled, coalesce(h.identity_domain, ''), coalesce(h.identity_realm, ''),
		       h.identity_sssd_online, h.identity_checked_at,
		       coalesce(c.rejestr, '[]'::json)
		from hosts h
		left join lateral (
		    select json_agg(json_build_object(
		               'name', r.name, 'version', r.version,
		               'available', r.available, 'read_only', r.read_only,
		               'reason', r.reason, 'features', r.features)
		           order by r.name) as rejestr
		      from host_capability_registry r where r.host_id = h.id
		) c on true
		` + clause

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.MachineID, &h.Hostname, &h.Site, &h.Environment, &h.Owner,
			&h.LifecycleState, &h.OSFamily, &h.OSDistribution, &h.OSVersion, &h.Architecture,
			&h.AgentVersion, &h.ConnectionState, &h.LastSeenAt, &h.BootID,
			&h.RebootRequired, &h.FailedUnits, &h.PendingUpdates, &h.PendingSecurityUpdates,
			&h.CurrentInventoryRevision, &h.PackageDatabaseBroken, &h.EnrolledAt,
			&h.ManagementAddress, &h.ManagementAddressSource, &h.ManagementAddressObservedAt,
			&h.Identity.Enrolled, &h.Identity.Domain, &h.Identity.Realm,
			&h.Identity.SSSDOnline, &h.Identity.CheckedAt,
			&h.Capabilities); err != nil {
			return nil, err
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

// Zrodla adresu zarzadzania. Kolejnosc nie jest przypadkowa: adres ustawiony
// recznie przez operatora opisuje intencje, a nie obserwacje, wiec nie moze
// zostac nadpisany przez kolejne polaczenie.
const (
	AddressFromSession = "session"
	AddressFromAgent   = "agent"
	AddressFromManual  = "manual"
)

// SetManagementAddress zapisuje adres zarzadzania wraz z jego pochodzeniem.
// Pusty adres nie jest zapisywany: brak obserwacji nie jest faktem o hoscie
// i nie moze skasowac adresu, ktory znamy z poprzedniego polaczenia.
func (s *Store) SetManagementAddress(ctx context.Context, hostID, address, source string) error {
	if address == "" || source == "" {
		return nil
	}
	const query = `
		update hosts
		   set management_address             = $2,
		       management_address_source       = $3,
		       management_address_observed_at  = now(),
		       updated_at                      = now()
		 where id = $1
		   and coalesce(management_address_source, '') <> 'manual'`
	_, err := s.pool.Exec(ctx, query, hostID, address, source)
	return err
}

// AdoptCertificateIssuer uzupelnia wystawce certyfikatow sprzed wprowadzenia
// wymiany CA. Wolno to zrobic wylacznie wtedy, gdy istnieje dokladnie jedno
// CA - przy wiekszej liczbie wystawcy nie da sie ustalic inaczej niz zgadujac,
// a zgadniety wystawca prowadzilby do odciecia hostow przy wycofaniu CA.
func (s *Store) AdoptCertificateIssuer(ctx context.Context, subject, serial string) (int64, error) {
	const query = `
		update agent_certificates set issuer_subject = $1, issuer_serial = $2
		where issuer_subject is null`
	tag, err := s.pool.Exec(ctx, query, subject, serial)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CertificateIssuers liczy hosty wedlug CA, ktore wystawilo ich obecny,
// nieodwolany certyfikat. Klucz mapy to "podmiot numer_seryjny" wystawcy.
//
// Bez tej wiedzy wycofanie CA byloby zgadywaniem: nie widac, ilu hostom
// odbiera sie dostep.
func (s *Store) CertificateIssuers(ctx context.Context) (map[string]int, error) {
	const query = `
		select coalesce(issuer_subject, ''), coalesce(issuer_serial, ''), count(*)
		from agent_certificates
		where revoked_at is null and not_after > now()
		group by 1, 2`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	uzycie := map[string]int{}
	for rows.Next() {
		var subject, serial string
		var count int
		if err := rows.Scan(&subject, &serial, &count); err != nil {
			return nil, err
		}
		uzycie[subject+" "+serial] = count
	}
	return uzycie, rows.Err()
}

// HostsWithoutCertificateSince liczy hosty, ktore od podanej chwili nie
// dostaly nowego certyfikatu.
//
// Sluzy do wymiany CA: agent poznaje nowe CA razem z certyfikatem, wiec host
// bez swiezego certyfikatu nie ma jeszcze nowego CA u siebie. Przekazanie mu
// podpisywania odcieloby taki host przy najblizszym restarcie panelu.
//
// Liczy sie chwila wydania certyfikatu, a nie poczatek jego waznosci: ten
// drugi jest celowo cofniety na poczet rozjazdu zegarow i swiezo wydany
// certyfikat wygladalby przez to na starszy, niz jest.
func (s *Store) HostsWithoutCertificateSince(ctx context.Context, since time.Time) (int, error) {
	const query = `
		select count(*)
		from hosts h
		where h.lifecycle_state <> 'decommissioned'
		  and not exists (
		      select 1 from agent_certificates c
		      where c.host_id = h.id and c.revoked_at is null and c.created_at >= $1
		  )`
	var count int
	if err := s.pool.QueryRow(ctx, query, since).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
