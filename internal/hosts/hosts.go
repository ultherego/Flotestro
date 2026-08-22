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

// Capabilities opisuje wykryte na hoscie adaptery.
type Capabilities struct {
	Systemd  bool `json:"systemd"`
	APT      bool `json:"apt"`
	DNF      bool `json:"dnf"`
	Docker   bool `json:"docker"`
	Journald bool `json:"journald"`
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
	RebootRequired           *bool        `json:"reboot_required"`
	FailedUnits              *int         `json:"failed_units"`
	PendingUpdates           *int         `json:"pending_updates"`
	PendingSecurityUpdates   *int         `json:"pending_security_updates"`
	CurrentInventoryRevision string       `json:"current_inventory_revision,omitempty"`
	PackageDatabaseBroken    bool         `json:"package_database_broken"`
	Identity                 HostIdentity `json:"identity"`
	EnrolledAt               time.Time    `json:"enrolled_at"`
	Capabilities             Capabilities `json:"capabilities"`
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
	fingerprint []byte, notBefore, notAfter time.Time) error {
	const query = `
		insert into agent_certificates
			(id, host_id, serial, fingerprint_sha256, subject_common_name, not_before, not_after)
		values ($1, $2, $3, $4, $5, $6, $7)`
	_, err := tx.Exec(ctx, query, uuid.NewString(), hostID, serial, fingerprint, commonName, notBefore, notAfter)
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
}

// LookupCertificate sprawdza, czy certyfikat jest znany i nieodwolany oraz czy
// host nie jest w kwarantannie. Gateway odrzuca sesje na podstawie tego wyniku.
func (s *Store) LookupCertificate(ctx context.Context, fingerprint []byte) (CertificateStatus, error) {
	const query = `
		select c.host_id, h.lifecycle_state, c.revoked_at is not null
		from agent_certificates c
		join hosts h on h.id = c.host_id
		where c.fingerprint_sha256 = $1`
	var status CertificateStatus
	err := s.pool.QueryRow(ctx, query, fingerprint).
		Scan(&status.HostID, &status.LifecycleState, &status.Revoked)
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

	detail, err := json.Marshal(caps)
	if err != nil {
		return err
	}
	const capQuery = `
		insert into host_capabilities (host_id, systemd, apt, dnf, docker, journald, detail, observed_at)
		values ($1, $2, $3, $4, $5, $6, $7, now())
		on conflict (host_id) do update set
			systemd = excluded.systemd, apt = excluded.apt, dnf = excluded.dnf,
			docker = excluded.docker, journald = excluded.journald,
			detail = excluded.detail, observed_at = excluded.observed_at`
	if _, err := tx.Exec(ctx, capQuery, hostID,
		caps.Systemd, caps.APT, caps.DNF, caps.Docker, caps.Journald, detail); err != nil {
		return fmt.Errorf("aktualizacja capabilities: %w", err)
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
		       h.identity_enrolled, coalesce(h.identity_domain, ''), coalesce(h.identity_realm, ''),
		       h.identity_sssd_online, h.identity_checked_at,
		       coalesce(c.systemd, false), coalesce(c.apt, false), coalesce(c.dnf, false),
		       coalesce(c.docker, false), coalesce(c.journald, false)
		from hosts h
		left join host_capabilities c on c.host_id = h.id
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
			&h.Identity.Enrolled, &h.Identity.Domain, &h.Identity.Realm,
			&h.Identity.SSSDOnline, &h.Identity.CheckedAt,
			&h.Capabilities.Systemd, &h.Capabilities.APT, &h.Capabilities.DNF,
			&h.Capabilities.Docker, &h.Capabilities.Journald); err != nil {
			return nil, err
		}
		result = append(result, h)
	}
	return result, rows.Err()
}
