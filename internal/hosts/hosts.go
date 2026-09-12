// Package hosts stores the identity and state of hosts. The package knows
// neither the HTTP layer nor the agent protocol; mapping the contracts belongs
// to the gateway.
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

// ErrNotFound means there is no host with the given identity.
var ErrNotFound = errors.New("the host does not exist")

// Capability describes one adapter discovered on a host. The name says what
// the host has ('packages.apt'), not what an operation wants ('packages').
type Capability struct {
	Name      string          `json:"name"`
	Version   uint32          `json:"version"`
	Available bool            `json:"available"`
	ReadOnly  bool            `json:"read_only"`
	Reason    string          `json:"reason,omitempty"`
	Features  map[string]bool `json:"features,omitempty"`
}

// Capabilities is the registry of a host's adapters.
type Capabilities []Capability

// The names of the adapters and the requirements of operations. A
// requirement is a logical name: an upgrade operation is not to know whether
// the host uses apt or dnf.
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
	CapSSHD      = "sshd"
	CapKernel    = "kernel"
	CapFiles     = "files.managed"

	NeedPackages      = "packages"
	NeedPackageRepair = "packages.repair"
	// Writing the network configuration. Reading works everywhere iproute2
	// is, so the module alone does not yet say that anything can be changed
	// here.
	NeedNetworkWrite  = "network.write"
	NeedDNSWrite      = "dns.write"
	NeedFirewallWrite = "firewall.write"
	NeedFirewallZones = "firewall.zones"
	NeedLVM           = "storage.lvm"
)

// Available says whether the adapter with this name works on the host.
func (c Capabilities) Available(name string) bool {
	for _, capability := range c {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}

// Feature says whether the adapter has the given part.
func (c Capabilities) Feature(name, feature string) bool {
	value, _ := c.FeatureState(name, feature)
	return value
}

// FeatureState separates "it does not have this part" from "it is not known
// whether it has it".
//
// An agent from before the registry sends no features at all, and its
// registry is reconstructed from logical fields. Treating silence as a
// refusal would take away from such a host an operation that works on it - an
// unknown feature is not an absent feature.
func (c Capabilities) FeatureState(name, feature string) (value bool, known bool) {
	for _, capability := range c {
		if capability.Name != name {
			continue
		}
		if !capability.Available {
			// An adapter that is not there certainly has no parts.
			return false, true
		}
		value, ok := capability.Features[feature]
		return value, ok
	}
	// The adapter is not in the registry - that is an answer too, not ignorance.
	return false, true
}

// Reason returns the explanation recorded by the host. The interface is to
// repeat what the host said rather than guess the cause in browser code.
func (c Capabilities) Reason(name string) string {
	for _, capability := range c {
		if capability.Name == name {
			return capability.Reason
		}
	}
	return ""
}

// Satisfies checks an operation's requirement against the host's registry.
func (c Capabilities) Satisfies(requirement string) bool {
	switch requirement {
	case "":
		return true
	case NeedPackages:
		return c.Available(CapAPT) || c.Available(CapDNF)
	case NeedPackageRepair:
		for _, adapter := range []string{CapAPT, CapDNF} {
			value, known := c.FeatureState(adapter, "repair")
			if value {
				return true
			}
			// The adapter is present but silent about its features: the host
			// decides at execution time, as it did before the registry was
			// introduced.
			if !known && c.Available(adapter) {
				return true
			}
		}
		return false
	case NeedFirewallWrite:
		value, known := c.FeatureState(CapFirewall, "write")
		if value {
			return true
		}
		return !known && c.Available(CapFirewall)
	case NeedLVM:
		// Extending a volume makes sense only where LVM exists at all.
		value, _ := c.FeatureState(CapStorage, "lvm")
		return value
	case NeedFirewallZones:
		value, _ := c.FeatureState(CapFirewall, "zones")
		return value
	case NeedDNSWrite:
		value, known := c.FeatureState(CapDNS, "write")
		if value {
			return true
		}
		return !known && c.Available(CapDNS)
	case NeedNetworkWrite:
		// Writing the network requires a mechanism that persists the change
		// and allows rolling it back. A host without one is to learn about it
		// when the operation is ordered, not after the task is delivered.
		value, known := c.FeatureState(CapNetwork, "write")
		if value {
			return true
		}
		// The adapter is present but silent about its features: the host
		// decides at execution time, as it did before the registry was
		// introduced.
		return !known && c.Available(CapNetwork)
	default:
		return c.Available(requirement)
	}
}

// Health is the minimal set of signals from a heartbeat. An empty pointer
// means a state the agent did not determine and does not overwrite the last
// known value.
type Health struct {
	FailedUnits            *uint32
	RebootRequired         *bool
	Load1Milli             uint32
	RootFSUsedPercent      uint32
	UptimeSeconds          uint64
	PendingUpdates         *uint32
	PendingSecurityUpdates *uint32
}

// Identity is the data reported at enrollment.
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

// Host is the view of a host returned by the API.
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
	// Empty fields mean an undetermined state, not zero.
	RebootRequired           *bool  `json:"reboot_required"`
	FailedUnits              *int   `json:"failed_units"`
	PendingUpdates           *int   `json:"pending_updates"`
	PendingSecurityUpdates   *int   `json:"pending_security_updates"`
	CurrentInventoryRevision string `json:"current_inventory_revision,omitempty"`
	PackageDatabaseBroken    bool   `json:"package_database_broken"`
	// The management address and where it came from. Empty fields mean an
	// undetermined address; the interface is then to say "unknown" rather
	// than show any address of the host as a supposed management address.
	ManagementAddress           string     `json:"management_address,omitempty"`
	ManagementAddressSource     string     `json:"management_address_source,omitempty"`
	ManagementAddressObservedAt *time.Time `json:"management_address_observed_at,omitempty"`
	// Maintenance is the maintenance window. An empty field means a host
	// outside a window, not a window of zero length.
	Maintenance  *MaintenanceWindow `json:"maintenance,omitempty"`
	Identity     HostIdentity       `json:"identity"`
	EnrolledAt   time.Time          `json:"enrolled_at"`
	Capabilities Capabilities       `json:"capabilities"`
}

// MaintenanceWindow describes a host's maintenance window.
//
// A host inside a window runs and accepts manually ordered operations;
// campaigns skip it, and its alerts do not wake the on-call engineer. A
// window always has an end: "until further notice" ends with a host everybody
// forgot about.
type MaintenanceWindow struct {
	Until  time.Time `json:"until"`
	Reason string    `json:"reason,omitempty"`
	SetBy  string    `json:"set_by,omitempty"`
	SetAt  time.Time `json:"set_at"`
}

// Active says whether the window is in force at the given moment.
func (m *MaintenanceWindow) Active(now time.Time) bool {
	return m != nil && now.Before(m.Until)
}

// HostIdentity describes the host's integration with a domain in the API view.
type HostIdentity struct {
	Enrolled   bool       `json:"enrolled"`
	Domain     string     `json:"domain,omitempty"`
	Realm      string     `json:"realm,omitempty"`
	SSSDOnline *bool      `json:"sssd_online"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

// Store provides access to the host tables.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Upsert creates a host or updates its identifying data. The identity key is
// machine_id, so enrolling the same machine again does not create a
// duplicate.
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
		return "", false, fmt.Errorf("upserting the host: %w", err)
	}
	return hostID, created, nil
}

// IDByMachineID returns the host with this machine identifier.
//
// An empty value means "the panel does not know such a machine" - and that is
// an answer rather than an error: enrolling a new host rests on exactly
// that.
func (s *Store) IDByMachineID(ctx context.Context, tx pgx.Tx, machineID string) (string, error) {
	if machineID == "" {
		return "", nil
	}
	var hostID string
	err := tx.QueryRow(ctx, `select id::text from hosts where machine_id = $1`, machineID).Scan(&hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading the host by machine_id: %w", err)
	}
	return hostID, nil
}

// AdoptMachine binds an existing host to a new machine.
//
// Used when restoring an identity: a reinstalled host has a new machine_id
// but is the same host in the panel - with the same history, the same tasks
// and the same place in the fleet. Creating a second row for it would leave a
// dead twin in the panel.
func (s *Store) AdoptMachine(ctx context.Context, tx pgx.Tx, hostID string, id Identity) error {
	const query = `
		update hosts set
			machine_id    = $2,
			hostname      = coalesce(nullif($3, ''), hostname),
			os_family     = coalesce(nullif($4, ''), os_family),
			os_version    = coalesce(nullif($5, ''), os_version),
			architecture  = coalesce(nullif($6, ''), architecture),
			agent_version = coalesce(nullif($7, ''), agent_version),
			updated_at    = now()
		where id = $1::uuid`
	tag, err := tx.Exec(ctx, query, hostID, id.MachineID, id.Hostname,
		id.OSFamily, id.OSVersion, id.Architecture, id.AgentVersion)
	if err != nil {
		return fmt.Errorf("adopting the machine into the host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("the host %s does not exist", hostID)
	}
	return nil
}

// The host lifecycle states.
//
// Only an active host gets tasks, sessions, secrets and renewals. The other
// states are different kinds of "no" and each means something else to the
// operator: quarantine is reversible, retiring is under way, retired is the
// end of trust.
const (
	StateActive      = "active"
	StateQuarantined = "quarantined"
	StateRetiring    = "retiring"
	StateRetired     = "retired"
)

// Active says whether in this state the panel may order the host anything.
func Active(state string) bool { return state == StateActive }

// ErrForbiddenTransition means a state change that must not be carried out.
var ErrForbiddenTransition = errors.New("forbidden lifecycle transition")

// ChangeLifecycleState moves a host between lifecycle states.
//
// The transition is conditional and runs in a single query: two orders issued
// at once must not end with a host that is both retired and restored. The
// allowed source states are part of the caller's decision.
func (s *Store) ChangeLifecycleState(ctx context.Context, tx pgx.Tx, hostID string,
	fromStates []string, newState, reason, actor string) error {
	const query = `
		update hosts set
			lifecycle_state      = $2,
			lifecycle_reason     = $3,
			lifecycle_changed_at = now(),
			lifecycle_changed_by = $4,
			retired_at           = case when $2 = 'retired' then now() else retired_at end,
			updated_at           = now()
		where id = $1::uuid and lifecycle_state = any($5)`
	tag, err := tx.Exec(ctx, query, hostID, newState, reason, actor, fromStates)
	if err != nil {
		return fmt.Errorf("changing the lifecycle state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrForbiddenTransition
	}
	return nil
}

// RevokeCertificates invalidates every valid certificate of a host.
//
// Used when the host's key may have leaked or when the host leaves the fleet:
// the certificate stays cryptographically valid, so without this record a
// captured machine would still introduce itself to the panel successfully.
func (s *Store) RevokeCertificates(ctx context.Context, tx pgx.Tx, hostID, reason string) (int, error) {
	const query = `
		update agent_certificates set revoked_at = now(), revocation_reason = $2
		where host_id = $1::uuid and revoked_at is null`
	tag, err := tx.Exec(ctx, query, hostID, reason)
	if err != nil {
		return 0, fmt.Errorf("revoking the certificates: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SaveCertificate records an issued agent certificate.
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
		return fmt.Errorf("saving the certificate: %w", err)
	}
	return nil
}

// CertificateStatus describes the state of a certificate presented by an agent.
type CertificateStatus struct {
	HostID         string
	LifecycleState string
	Revoked        bool
	Known          bool
	// Serial identifies the certificate in the audit trail; on a renewal it
	// allows linking the new certificate with the replaced one.
	Serial string
}

// LookupCertificate checks whether the certificate is known and not revoked
// and whether the host is not in quarantine. The gateway rejects sessions
// based on this result.
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

// ApplyHello records the session data reported in the first message of the stream.
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
		return fmt.Errorf("updating the host: %w", err)
	}

	// The registry is replaced in full: an adapter the host no longer reports
	// has disappeared from the host and must not stay in the database as a
	// stale truth.
	const deleteQuery = `delete from host_capability_registry where host_id = $1`
	if _, err := tx.Exec(ctx, deleteQuery, hostID); err != nil {
		return fmt.Errorf("clearing the adapter registry: %w", err)
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
			return fmt.Errorf("updating the adapter %s: %w", capability.Name, err)
		}
	}
	return tx.Commit(ctx)
}

// ApplyHeartbeat records the minimal health signals and refreshes
// last_seen_at. A signal the agent did not determine leaves the previous
// value untouched: a momentary read failure on the host must neither delete
// what we already know nor pretend to be zero.
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

// countArg turns an undetermined counter into NULL for the query.
func countArg(value *uint32) any {
	if value == nil {
		return nil
	}
	return int(*value)
}

// SetPackageDatabaseBroken records whether the host's package database needs
// repair. A host in this state cannot take part in further campaigns.
func (s *Store) SetPackageDatabaseBroken(ctx context.Context, hostID string, broken bool) error {
	const query = `update hosts set package_database_broken = $2, updated_at = now() where id = $1`
	_, err := s.pool.Exec(ctx, query, hostID, broken)
	return err
}

// MarkDisconnected marks a host as offline after the stream closes.
func (s *Store) MarkDisconnected(ctx context.Context, hostID string) error {
	const query = `update hosts set connection_state = 'offline', updated_at = now() where id = $1`
	_, err := s.pool.Exec(ctx, query, hostID)
	return err
}

// Get returns a single host.
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

// ListFilter describes the filters applied on the server's side.
type ListFilter struct {
	Site            string
	Environment     string
	OSFamily        string
	ConnectionState string
	// IdentityDomain narrows to the hosts in a given domain.
	IdentityDomain string
	Limit          int
}

// List returns the hosts matching the filter. Filtering happens in the
// database; the UI never pulls the whole fleet into the browser's memory.
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

// Page returns the next page of hosts matching the filter.
//
// A campaign must not have a hidden limit: a selector covering a thousand
// hosts has to mean a thousand hosts, not the first five hundred sorted
// alphabetically. Paging goes by the key (hostname, id) rather than by an
// offset - the fleet changes while it is being browsed, and an offset then
// loses hosts in the middle.
//
// The first page is taken with an empty key.
func (s *Store) Page(ctx context.Context, filter ListFilter,
	afterName, afterID string, limit int) ([]Host, error) {
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

	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	args = append(args, afterName, afterID)
	conditions = append(conditions, fmt.Sprintf("($%d = '' or (h.hostname, h.id) > ($%d, $%d::uuid))",
		len(args)-1, len(args)-1, len(args)))

	if limit <= 0 {
		limit = PageSize
	}
	args = append(args, limit)
	clause := "where " + strings.Join(conditions, " and ") +
		fmt.Sprintf(" order by h.hostname, h.id limit $%d", len(args))

	return s.query(ctx, clause, args...)
}

// Count returns the number of hosts matching the filter.
//
// A campaign preview has to give the true number of targets rather than the
// length of the first page: the operator approves a change on as many hosts
// as they were shown.
func (s *Store) Count(ctx context.Context, filter ListFilter) (int, error) {
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
	add("site", filter.Site)
	add("environment", filter.Environment)
	add("os_family", filter.OSFamily)
	add("connection_state", filter.ConnectionState)
	add("identity_domain", filter.IdentityDomain)

	query := "select count(*) from hosts"
	if len(conditions) > 0 {
		query += " where " + strings.Join(conditions, " and ")
	}
	var count int
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Summary is what a sweep over the whole fleet needs to know about a host.
//
// A sweep is not a list for the UI: it has neither a limit from a filter nor
// the capability registry, because it is to cover every host rather than the
// first page.
type Summary struct {
	ID             string
	Hostname       string
	OSDistribution string
	OSVersion      string
}

// PageSize is the size of one page of a sweep.
const PageSize = 500

// Sweep returns the next page of the fleet in the order of the key
// (hostname, id).
//
// Paging by key rather than by offset: the fleet changes during a sweep, and
// an offset then loses hosts in the middle. A sweep that silently skips hosts
// gives the verdict "no vulnerabilities" where nobody looked.
//
// The first page is taken with an empty key.
func (s *Store) Sweep(ctx context.Context, afterName, afterID string, limit int) ([]Summary, error) {
	if limit <= 0 {
		limit = PageSize
	}
	query := `
		select h.id, h.hostname, coalesce(h.os_distribution, ''), coalesce(h.os_version, '')
		from hosts h
		where ($1 = '' or (h.hostname, h.id) > ($1, $2::uuid))
		order by h.hostname, h.id
		limit $3`
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := s.pool.Query(ctx, query, afterName, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Summary
	for rows.Next() {
		var summary Summary
		if err := rows.Scan(&summary.ID, &summary.Hostname, &summary.OSDistribution,
			&summary.OSVersion); err != nil {
			return nil, err
		}
		result = append(result, summary)
	}
	return result, rows.Err()
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
		       h.maintenance_until, coalesce(h.maintenance_reason, ''),
		       coalesce(h.maintenance_by, ''), h.maintenance_at,
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
		var windowUntil, windowFrom *time.Time
		var windowReason, windowBy string
		if err := rows.Scan(&h.ID, &h.MachineID, &h.Hostname, &h.Site, &h.Environment, &h.Owner,
			&h.LifecycleState, &h.OSFamily, &h.OSDistribution, &h.OSVersion, &h.Architecture,
			&h.AgentVersion, &h.ConnectionState, &h.LastSeenAt, &h.BootID,
			&h.RebootRequired, &h.FailedUnits, &h.PendingUpdates, &h.PendingSecurityUpdates,
			&h.CurrentInventoryRevision, &h.PackageDatabaseBroken, &h.EnrolledAt,
			&h.ManagementAddress, &h.ManagementAddressSource, &h.ManagementAddressObservedAt,
			&h.Identity.Enrolled, &h.Identity.Domain, &h.Identity.Realm,
			&h.Identity.SSSDOnline, &h.Identity.CheckedAt,
			&windowUntil, &windowReason, &windowBy, &windowFrom,
			&h.Capabilities); err != nil {
			return nil, err
		}
		// A closed or expired window is not a window: we show it only while
		// it is still in force.
		if windowUntil != nil {
			window := MaintenanceWindow{Until: *windowUntil, Reason: windowReason, SetBy: windowBy}
			if windowFrom != nil {
				window.SetAt = *windowFrom
			}
			h.Maintenance = &window
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

// The sources of the management address. The order is not accidental: an
// address set manually by an operator describes an intent rather than an
// observation, so it must not be overwritten by the next connection.
const (
	AddressFromSession = "session"
	AddressFromAgent   = "agent"
	AddressFromManual  = "manual"
)

// SetManagementAddress records the management address together with where it
// came from. An empty address is not recorded: a missing observation is not a
// fact about the host and must not delete the address we know from the
// previous connection.
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

// AdoptCertificateIssuer fills in the issuer of certificates from before CA
// rotation was introduced. It may be done only when exactly one CA exists -
// with more of them the issuer cannot be established other than by guessing,
// and a guessed issuer would lead to hosts being cut off when a CA is
// withdrawn.
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

// CertificateIssuers counts hosts by the CA that issued their current,
// unrevoked certificate. The map key is the issuer's "subject serial".
//
// Without that knowledge withdrawing a CA would be guesswork: it is not
// visible how many hosts lose access.
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

	usage := map[string]int{}
	for rows.Next() {
		var subject, serial string
		var count int
		if err := rows.Scan(&subject, &serial, &count); err != nil {
			return nil, err
		}
		usage[subject+" "+serial] = count
	}
	return usage, rows.Err()
}

// HostsWithoutCertificateSince counts the hosts that have not received a new
// certificate since the given moment.
//
// It serves CA rotation: the agent learns the new CA together with its
// certificate, so a host without a fresh certificate does not have the new CA
// yet. Handing signing over to it would cut such a host off at the panel's
// next restart.
//
// What counts is the moment the certificate was issued rather than the start
// of its validity: the latter is deliberately backdated to allow for clock
// skew, and a freshly issued certificate would therefore look older than it
// is.
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

// SetMaintenanceWindow opens or closes a host's maintenance window.
//
// Closing the window also clears the reason and the author: a reason left
// behind would describe a window that no longer exists and would look current
// the next time one is opened.
func (s *Store) SetMaintenanceWindow(ctx context.Context, hostID string,
	until *time.Time, reason, actor string) (*Host, error) {
	tag, err := s.pool.Exec(ctx, `
		update hosts
		   set maintenance_until  = $2::timestamptz,
		       maintenance_reason = case when $2::timestamptz is null then null else $3::text end,
		       maintenance_by     = case when $2::timestamptz is null then null else $4::text end,
		       maintenance_at     = case when $2::timestamptz is null then null else now() end
		 where id = $1`, hostID, until, reason, actor)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}
