// Package hosts stores the identity and state of hosts. The package knows
// neither the HTTP layer nor the agent protocol; mapping the contracts belongs
// to the gateway.
package hosts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/agentconfig"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/paging"
	"github.com/ultherego/flotestro/internal/selector"
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
	CapPacman    = "packages.pacman"
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
		return c.Available(CapAPT) || c.Available(CapDNF) || c.Available(CapPacman)
	case NeedPackageRepair:
		for _, adapter := range []string{CapAPT, CapDNF, CapPacman} {
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
	ID          string `json:"id"`
	MachineID   string `json:"machine_id"`
	Hostname    string `json:"hostname"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Owner       string `json:"owner,omitempty"`
	// FailureDomain is what the host goes down with - a rack, an
	// availability zone, a cluster whose members keep a service alive -
	// recorded by an operator, and keyed on by the budgets that keep a
	// campaign from taking a whole domain off at once. Absent for a host
	// nobody placed: an unknown domain is not a shared one.
	FailureDomain  string `json:"failure_domain,omitempty"`
	LifecycleState string `json:"lifecycle_state"`
	// LifecycleReason and LifecycleChangedAt are the decision behind a
	// state other than active: who cut the host off and why is part of the
	// host, not a line to dig out of the audit trail.
	LifecycleReason    string     `json:"lifecycle_reason,omitempty"`
	LifecycleChangedAt *time.Time `json:"lifecycle_changed_at,omitempty"`
	OSFamily           string     `json:"os_family,omitempty"`
	OSDistribution     string     `json:"os_distribution,omitempty"`
	OSVersion          string     `json:"os_version,omitempty"`
	Architecture       string     `json:"architecture,omitempty"`
	AgentVersion       string     `json:"agent_version,omitempty"`
	ConnectionState    string     `json:"connection_state"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
	BootID             string     `json:"boot_id,omitempty"`
	// What the agent reported about itself at its last Hello beyond the
	// version: the commit it was built from, the protocols it speaks, and
	// the configuration it runs on. Every field is absent for a host whose
	// agent predates the report - an unknown build is not an empty one.
	AgentBuildCommit string `json:"agent_build_commit,omitempty"`
	AgentProtocolMin *int   `json:"agent_protocol_min,omitempty"`
	AgentProtocolMax *int   `json:"agent_protocol_max,omitempty"`
	// ConfigFingerprint digests the effective agent.yaml; absent also for
	// a host on the environment variables of the old flow, which has no
	// file. ConfigSchemaVersion is what the file declares, zero for no
	// file, and ConfigLegacy is the verdict: the host runs on the
	// environment file or on a schema older than the current one. Absent
	// when the agent reported nothing: not knowing is not "legacy".
	ConfigFingerprint   string `json:"config_fingerprint,omitempty"`
	ConfigSchemaVersion *int   `json:"config_schema_version,omitempty"`
	ConfigLegacy        *bool  `json:"config_legacy,omitempty"`
	// Tags are what operators recorded about the host: 'key' or
	// 'key=value'. The list is always present - a host without tags has an
	// empty one - so a selector can tell "no tags" from "not asked".
	Tags []string `json:"tags"`
	// ReleaseChannel says which agent releases the host follows: stable or
	// beta. It is a policy recorded in the panel, always set - a host on no
	// channel would follow nothing.
	ReleaseChannel string `json:"release_channel"`
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
	Maintenance *MaintenanceWindow `json:"maintenance,omitempty"`
	// LastConnectionRefusal is why the gateway last turned the host away
	// since its last session. Absent for a host that connected the last
	// time it tried: a session that opens clears it, so an old refusal
	// never outlives a reconnect.
	LastConnectionRefusal *ConnectionRefusal `json:"last_connection_refusal,omitempty"`
	Identity              HostIdentity       `json:"identity"`
	EnrolledAt            time.Time          `json:"enrolled_at"`
	Capabilities          Capabilities       `json:"capabilities"`
}

// ConnectionRefusal is the reason the gateway would not open a session for
// the host, as the host page and the fleet list show it.
type ConnectionRefusal struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
	// Detail is what the gateway saw - the serial and the validity of the
	// certificate, or the state of the host - for the operator who wants
	// more than the code.
	Detail string `json:"detail,omitempty"`
}

// The refusal codes of the gateway. The certificate ones name the
// certificate the host presented; a lifecycle refusal is spelled as
// lifecycle_<state> and is a decision of an operator rather than a fault of
// the host.
const (
	// RefusalCertificateExpired is an agent that missed its renewal: the
	// remedy is an identity recovery ordered from the panel.
	RefusalCertificateExpired = "certificate_expired"
	// RefusalCertificateNotYetValid is a certificate from the future -
	// the clock of the host or of the panel is wrong.
	RefusalCertificateNotYetValid = "certificate_not_yet_valid"
	// RefusalUnknownCertificate is a certificate the panel never issued or
	// no longer has on record.
	RefusalUnknownCertificate = "unknown_certificate"
	// RefusalRevokedCertificate is a certificate an operator or a
	// replacement withdrew.
	RefusalRevokedCertificate = "revoked_certificate"
	// RefusalIdentityMismatch is a certificate on record for another host
	// than the one it names.
	RefusalIdentityMismatch = "identity_mismatch"
)

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
	// OfflineVerdict is the panel's judgement on directory logins during an
	// outage, from the facts the host reported. Absent for a host outside a
	// domain: there is nothing to judge.
	OfflineVerdict *OfflineVerdict `json:"offline_verdict,omitempty"`
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
// operator: quarantine is reversible, recovery waits for a new key, retiring
// is under way, retired is the end of trust.
const (
	StateActive      = "active"
	StateQuarantined = "quarantined"
	// StateRecovery is the host between an identity recovery order and the
	// first session of the new certificate. No operation and no secret, as
	// in quarantine; the old certificate may still open a session for the
	// overlap, so that the operator keeps reading the host until the new
	// key has proven it works.
	StateRecovery = "recovery"
	// StateRetiring is the host in the decommission handshake: the final
	// task went out and the host is finishing what it started.
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

// RecoveryOverlap is how long the certificate replaced by a recovery may
// still open a session. Long enough to cover a reinstall that takes a day;
// short enough that a key nobody replaced does not keep working for good.
const RecoveryOverlap = 24 * time.Hour

// RetiredMachineRetention is how long the machine identifier of a retired
// host is refused for a "new host" token.
const RetiredMachineRetention = 30 * 24 * time.Hour

// Active says whether in this state the panel may order the host anything.
func Active(state string) bool { return state == StateActive }

// Connectable says whether a certificate of a host in this state may open a
// session at the given moment. Only an active host connects without a
// condition; a host in recovery connects while the overlap since the order
// lasts, so that the operator can still read it with the old key.
func Connectable(state string, changedAt *time.Time, now time.Time) bool {
	switch state {
	case StateActive:
		return true
	case StateRecovery:
		return changedAt != nil && now.Before(changedAt.Add(RecoveryOverlap))
	}
	return false
}

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
			retired_machine_id_until = case when $2 = 'retired' then now() + $6::interval
			                           else retired_machine_id_until end,
			updated_at           = now()
		where id = $1::uuid and lifecycle_state = any($5)`
	tag, err := tx.Exec(ctx, query, hostID, newState, reason, actor, fromStates, RetiredMachineRetention)
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

// LeaveRecovery moves a host from recovery back to active once a certificate
// issued after the recovery order has opened a session.
//
// The presented certificate is compared with the moment of the order rather
// than with "the newest one": the old certificate may still connect during
// the overlap, and its session must not close a recovery it has nothing to
// do with. The return value says whether the state changed.
func (s *Store) LeaveRecovery(ctx context.Context, hostID string, fingerprint []byte) (bool, error) {
	const query = `
		update hosts set
			lifecycle_state      = 'active',
			lifecycle_reason     = 'the identity was recovered',
			lifecycle_changed_at = now(),
			lifecycle_changed_by = 'agent',
			updated_at           = now()
		where id = $1::uuid and lifecycle_state = 'recovery'
		  and exists (select 1 from agent_certificates c
		              where c.host_id = hosts.id and c.fingerprint_sha256 = $2
		                and c.created_at >= coalesce(hosts.lifecycle_changed_at, c.created_at))`
	tag, err := s.pool.Exec(ctx, query, hostID, fingerprint)
	if err != nil {
		return false, fmt.Errorf("leaving the recovery state: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// LapseRecoveries returns to active the hosts whose recovery has nothing
// left to wait for: no pending recovery order, and no certificate issued
// since the order. The old key is then still the identity of the host, and
// keeping it cut off would punish it for an order somebody revoked or let
// expire. A host whose order was used stays in recovery until the new
// certificate opens its first session - that is what the state is for.
// The identifiers of the hosts that came back are returned for the trail.
func (s *Store) LapseRecoveries(ctx context.Context) ([]string, error) {
	const query = `
		update hosts h set
			lifecycle_state      = 'active',
			lifecycle_reason     = 'the recovery order lapsed without a new certificate',
			lifecycle_changed_at = now(),
			lifecycle_changed_by = 'panel',
			updated_at           = now()
		where h.lifecycle_state = 'recovery'
		  and not exists (select 1 from enrollment_requests r
		                  where r.expected_host_id = h.id and r.purpose = 'replace_identity'
		                    and r.revoked_at is null and r.expires_at > now()
		                    and r.uses < r.max_uses)
		  and not exists (select 1 from agent_certificates c
		                  where c.host_id = h.id and c.revoked_at is null
		                    and c.created_at >= coalesce(h.lifecycle_changed_at, c.created_at))
		returning h.id::text`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("lapsing the recoveries: %w", err)
	}
	defer rows.Close()
	var lapsed []string
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return nil, err
		}
		lapsed = append(lapsed, hostID)
	}
	return lapsed, rows.Err()
}

// RetiredMachine says whether the host with this identifier is retired, and
// until when its machine identifier is held back from "new host" tokens. A
// host that is not retired answers false with a zero time.
func (s *Store) RetiredMachine(ctx context.Context, tx pgx.Tx, hostID string) (retired bool, until time.Time, err error) {
	// A host retired before the hold existed gets the same retention from
	// its retirement: the rule is about the machine, not about the release
	// that introduced the column.
	const query = `
		select lifecycle_state = 'retired',
		       coalesce(retired_machine_id_until, retired_at + $2::interval, now())
		from hosts where id = $1::uuid`
	if err := tx.QueryRow(ctx, query, hostID, RetiredMachineRetention).Scan(&retired, &until); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, fmt.Errorf("reading the retired host: %w", err)
	}
	return retired, until, nil
}

// ReleaseMachineID frees the machine identifier of a retired host, so that
// the same machine can enter the fleet as a new host once the retention has
// passed. The retired row keeps its history under a marked identifier: the
// unique index on machine_id leaves no other way to have both rows.
func (s *Store) ReleaseMachineID(ctx context.Context, tx pgx.Tx, hostID string) error {
	const query = `
		update hosts set machine_id = 'retired:' || id::text || ':' || machine_id, updated_at = now()
		where id = $1::uuid and lifecycle_state = 'retired'`
	tag, err := tx.Exec(ctx, query, hostID)
	if err != nil {
		return fmt.Errorf("releasing the machine identifier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrForbiddenTransition
	}
	return nil
}

// RevokeSupersededCertificates revokes the certificates of a host older
// than the one it has just presented. A host has one identity at a time:
// once the new certificate has opened a session, the earlier ones - the
// one replaced by a recovery, or the one renewed from - are keys that
// nobody legitimate holds any more. The row of the presented certificate
// is the reference, so an unknown fingerprint revokes nothing.
func (s *Store) RevokeSupersededCertificates(ctx context.Context, hostID string,
	fingerprint []byte, reason string) (int, error) {
	const query = `
		update agent_certificates set revoked_at = now(), revocation_reason = $3
		where host_id = $1::uuid and revoked_at is null and not_after > now()
		  and fingerprint_sha256 <> $2
		  and created_at < (select created_at from agent_certificates
		                    where fingerprint_sha256 = $2 and host_id = $1::uuid)`
	tag, err := s.pool.Exec(ctx, query, hostID, fingerprint, reason)
	if err != nil {
		return 0, fmt.Errorf("revoking the superseded certificates: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// HasLiveCertificate says whether the host holds a certificate that is
// neither revoked nor expired. A host without one cannot come back on its
// own: its return starts with identity recovery.
func (s *Store) HasLiveCertificate(ctx context.Context, hostID string) (bool, error) {
	const query = `
		select exists (
			select 1 from agent_certificates
			where host_id = $1::uuid and revoked_at is null and not_after > now())`
	var live bool
	if err := s.pool.QueryRow(ctx, query, hostID).Scan(&live); err != nil {
		return false, fmt.Errorf("checking the certificates: %w", err)
	}
	return live, nil
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
	// LifecycleChangedAt is when the host entered its state. The recovery
	// overlap is counted from it.
	LifecycleChangedAt *time.Time
	Revoked            bool
	Known              bool
	// Serial identifies the certificate in the audit trail; on a renewal it
	// allows linking the new certificate with the replaced one.
	Serial string
}

// LookupCertificate checks whether the certificate is known and not revoked
// and whether the host is not in quarantine. The gateway rejects sessions
// based on this result.
func (s *Store) LookupCertificate(ctx context.Context, fingerprint []byte) (CertificateStatus, error) {
	const query = `
		select c.host_id, h.lifecycle_state, h.lifecycle_changed_at, c.revoked_at is not null, c.serial
		from agent_certificates c
		join hosts h on h.id = c.host_id
		where c.fingerprint_sha256 = $1`
	var status CertificateStatus
	err := s.pool.QueryRow(ctx, query, fingerprint).
		Scan(&status.HostID, &status.LifecycleState, &status.LifecycleChangedAt, &status.Revoked, &status.Serial)
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
			updated_at       = now(),
			last_connection_refusal_code   = null,
			last_connection_refusal_at     = null,
			last_connection_refusal_detail = null
		where id = $1`
	// The refusal goes with the session that opens: whatever kept the host
	// out is over, and a reason left standing would send the operator after
	// a fault the host no longer has.
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

// RecordConnectionRefusal writes down why the gateway turned the host away.
// The row keeps the newest refusal alone: the trail has every one of them,
// and the host needs only the reason it is not connected now.
//
// The identity comes from a certificate, so it is checked for the shape of
// an identifier before it reaches the query: a name that is not one matches
// no host, and must not turn into a query error either. False means no host
// of that identifier.
func (s *Store) RecordConnectionRefusal(ctx context.Context, hostID, code, detail string) (bool, error) {
	if _, err := uuid.Parse(hostID); err != nil {
		return false, nil
	}
	const query = `
		update hosts
		   set last_connection_refusal_code   = $2,
		       last_connection_refusal_at     = now(),
		       last_connection_refusal_detail = nullif($3, ''),
		       updated_at                     = now()
		 where id = $1`
	tag, err := s.pool.Exec(ctx, query, hostID, code, detail)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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
	// Search keeps the hosts with the text somewhere in the hostname, the
	// management address, the machine identifier or the owner. The
	// operator types what they remember about a host, and that is one of
	// those four things.
	Search         string
	LifecycleState string
	Owner          string
	// Maintenance keeps the hosts inside a maintenance window (true) or
	// outside one (false). Nil does not narrow.
	Maintenance *bool
	// RebootRequired keeps the hosts that need a reboot (true) or the ones
	// that reported they do not (false). A host that has not said either
	// way is in neither list: unknown is not "no".
	RebootRequired *bool
	// SecurityUpdates keeps the hosts with a security update waiting
	// (true) or with a count of none (false); unknown counts are left out
	// of both, for the same reason.
	SecurityUpdates *bool
	// Capability keeps the hosts whose registry has the named adapter
	// available; 'packages.apt', not 'packages'.
	Capability string
	// Tags keeps the hosts carrying every one of the given tags.
	Tags []string
	// Channel keeps the hosts on the given release channel.
	Channel string
	// ConnectionRefusal keeps the hosts the gateway last turned away for
	// the given reason, so the dashboard counter leads to the hosts it
	// counted.
	ConnectionRefusal string
	// IDs keeps the named hosts. Nil does not narrow; an empty list keeps
	// nothing, because a list of nobody names nobody.
	IDs []string
	// Expression is a selector already expanded of its group references;
	// it is compiled into the same query as the other filters, so a
	// campaign's targets and the host list answer the same question.
	Expression *selector.Expression
	// Scopes narrow the result to what the caller may read. Nil narrows
	// nothing, which is right only for a caller that has checked the scope
	// itself or has the global one.
	Scopes []authz.Scope
	Limit  int
}

// conditions renders the filter as SQL over the alias h. Every list of
// hosts - the page, the count and the plain list - goes through this one
// place, so a filter cannot work in the list and be forgotten in the count.
func (f ListFilter) conditions() ([]string, []any, error) {
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
	add("h.site", f.Site)
	add("h.environment", f.Environment)
	add("h.os_family", f.OSFamily)
	add("h.connection_state", f.ConnectionState)
	add("h.identity_domain", f.IdentityDomain)
	add("h.lifecycle_state", f.LifecycleState)
	add("h.owner", f.Owner)
	add("h.release_channel", f.Channel)
	add("h.last_connection_refusal_code", f.ConnectionRefusal)

	if f.Search != "" {
		// A tag is one of the things an operator remembers about a host,
		// so the search reads the tags as well as the names.
		args = append(args, "%"+escapeLike(f.Search)+"%")
		conditions = append(conditions, fmt.Sprintf(
			"(h.hostname ilike $%[1]d or h.management_address ilike $%[1]d"+
				" or h.machine_id ilike $%[1]d or h.owner ilike $%[1]d"+
				" or exists (select 1 from unnest(h.tags) tag where tag ilike $%[1]d))", len(args)))
	}
	if len(f.Tags) > 0 {
		// Containment: every given tag has to be on the host. The GIN
		// index on the column answers exactly this operator.
		args = append(args, f.Tags)
		conditions = append(conditions, fmt.Sprintf("h.tags @> $%d::text[]", len(args)))
	}
	if f.IDs != nil {
		// The identifiers travel as text and are cast in the query, so an
		// identifier list needs no guesswork about the driver's encoding.
		args = append(args, f.IDs)
		conditions = append(conditions, fmt.Sprintf("h.id in (select unnest($%d::text[])::uuid)", len(args)))
	}
	if f.Maintenance != nil {
		// A window is in force until its deadline; an expired one is no
		// window, even though its columns are still filled in.
		if *f.Maintenance {
			conditions = append(conditions, "h.maintenance_until > now()")
		} else {
			conditions = append(conditions, "(h.maintenance_until is null or h.maintenance_until <= now())")
		}
	}
	if f.RebootRequired != nil {
		// The column is null for a host that has not reported: a plain
		// comparison leaves it out of both answers, which is the point.
		conditions = append(conditions, fmt.Sprintf("h.reboot_required = %t", *f.RebootRequired))
	}
	if f.SecurityUpdates != nil {
		if *f.SecurityUpdates {
			conditions = append(conditions, "h.pending_security_updates > 0")
		} else {
			conditions = append(conditions, "h.pending_security_updates = 0")
		}
	}
	if f.Capability != "" {
		args = append(args, f.Capability)
		conditions = append(conditions, fmt.Sprintf(
			"exists (select 1 from host_capability_registry r"+
				" where r.host_id = h.id and r.name = $%d and r.available)", len(args)))
	}
	if f.Expression != nil {
		condition, extra, err := selector.Compile(f.Expression, len(args))
		if err != nil {
			return nil, nil, err
		}
		conditions = append(conditions, condition)
		args = append(args, extra...)
	}
	if f.Scopes != nil {
		// The narrowing rule lives next to the authorisation, so that a list
		// cannot show what a direct read would refuse.
		if condition, extra := authz.ScopeSQL(f.Scopes, "h.site", "h.environment", len(args)); condition != "" {
			conditions = append(conditions, condition)
			args = append(args, extra...)
		}
	}
	return conditions, args, nil
}

// escapeLike neutralises the pattern characters of a search. An operator
// looking for "db_01" means an underscore, not any character.
func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// List returns the hosts matching the filter. Filtering happens in the
// database; the UI never pulls the whole fleet into the browser's memory.
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Host, error) {
	conditions, args, err := filter.conditions()
	if err != nil {
		return nil, err
	}
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
	conditions, args, err := filter.conditions()
	if err != nil {
		return nil, err
	}

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
	conditions, args, err := filter.conditions()
	if err != nil {
		return 0, err
	}
	query := "select count(*) from hosts h"
	if len(conditions) > 0 {
		query += " where " + strings.Join(conditions, " and ")
	}
	var count int
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Cursor is the key of the last host of the previous page: its name and its
// identifier, the same key a sweep pages by.
type Cursor struct {
	Hostname string
	ID       string
	Set      bool
}

// ParseCursor reads a cursor issued by ListPaged. An empty value is the
// first page.
func ParseCursor(value string) (Cursor, error) {
	parts, err := paging.Decode(value, 2)
	if err != nil {
		return Cursor{}, err
	}
	if parts == nil {
		return Cursor{}, nil
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return Cursor{Hostname: parts[0], ID: parts[1], Set: true}, nil
}

// String renders the cursor for the next request.
func (c Cursor) String() string {
	return paging.Encode(c.Hostname, c.ID)
}

// ListPage is one page of the host list.
type ListPage struct {
	Items []Host `json:"items"`
	// Total is the number of hosts matching the filter across every page:
	// the operator is to know how many hosts a filter names, not how many
	// fit on the screen.
	Total int `json:"total"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListPaged reads the hosts matching the filter page by page, in the order
// of (hostname, id). The count comes with the page, so the screen can say
// how many hosts stand behind a filter without a second request.
func (s *Store) ListPaged(ctx context.Context, filter ListFilter, cursor Cursor, limit int) (ListPage, error) {
	page := ListPage{Items: []Host{}}
	total, err := s.Count(ctx, filter)
	if err != nil {
		return page, err
	}
	page.Total = total

	if limit <= 0 {
		limit = PageSize
	}
	// One row more than the page says whether there is a next page without
	// a second count.
	items, err := s.Page(ctx, filter, cursor.Hostname, cursor.ID, limit+1)
	if err != nil {
		return page, err
	}
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		page.NextCursor = Cursor{Hostname: last.Hostname, ID: last.ID, Set: true}.String()
	}
	if items != nil {
		page.Items = items
	}
	return page, nil
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
		select h.id, h.machine_id, h.hostname, h.site, h.environment, coalesce(h.owner, ''), h.tags,
		       coalesce(h.failure_domain, ''), h.release_channel,
		       h.lifecycle_state, h.lifecycle_reason, h.lifecycle_changed_at,
		       coalesce(h.os_family, ''), coalesce(h.os_distribution, ''),
		       coalesce(h.os_version, ''), coalesce(h.architecture, ''), coalesce(h.agent_version, ''),
		       h.connection_state, h.last_seen_at, coalesce(h.boot_id, ''),
		       coalesce(h.agent_build_commit, ''), h.agent_protocol_min, h.agent_protocol_max,
		       coalesce(h.config_fingerprint, ''), h.config_schema_version,
		       h.reboot_required, h.failed_units, h.pending_updates, h.pending_security_updates,
		       coalesce(h.current_inventory_revision, ''), h.package_database_broken, h.enrolled_at,
		       coalesce(h.management_address, ''), coalesce(h.management_address_source, ''),
		       h.management_address_observed_at,
		       h.identity_enrolled, coalesce(h.identity_domain, ''), coalesce(h.identity_realm, ''),
		       h.identity_sssd_online, h.identity_checked_at,
		       h.maintenance_until, coalesce(h.maintenance_reason, ''),
		       coalesce(h.maintenance_by, ''), h.maintenance_at,
		       coalesce(h.last_connection_refusal_code, ''), h.last_connection_refusal_at,
		       coalesce(h.last_connection_refusal_detail, ''),
		       coalesce(c.rejestr, '[]'::json),
		       i.payload, i.observed_at
		from hosts h
		left join lateral (
		    select json_agg(json_build_object(
		               'name', r.name, 'version', r.version,
		               'available', r.available, 'read_only', r.read_only,
		               'reason', r.reason, 'features', r.features)
		           order by r.name) as rejestr
		      from host_capability_registry r where r.host_id = h.id
		) c on true
		left join host_module_inventory i
		  on i.host_id = h.id and i.module = 'identity'
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
		var refusalCode, refusalDetail string
		var refusalAt *time.Time
		// The identity module rides along so the verdict on offline logins
		// is judged from the same facts the host tab shows.
		var identityPayload []byte
		var identityObservedAt *time.Time
		if err := rows.Scan(&h.ID, &h.MachineID, &h.Hostname, &h.Site, &h.Environment, &h.Owner, &h.Tags,
			&h.FailureDomain, &h.ReleaseChannel,
			&h.LifecycleState, &h.LifecycleReason, &h.LifecycleChangedAt,
			&h.OSFamily, &h.OSDistribution, &h.OSVersion, &h.Architecture,
			&h.AgentVersion, &h.ConnectionState, &h.LastSeenAt, &h.BootID,
			&h.AgentBuildCommit, &h.AgentProtocolMin, &h.AgentProtocolMax,
			&h.ConfigFingerprint, &h.ConfigSchemaVersion,
			&h.RebootRequired, &h.FailedUnits, &h.PendingUpdates, &h.PendingSecurityUpdates,
			&h.CurrentInventoryRevision, &h.PackageDatabaseBroken, &h.EnrolledAt,
			&h.ManagementAddress, &h.ManagementAddressSource, &h.ManagementAddressObservedAt,
			&h.Identity.Enrolled, &h.Identity.Domain, &h.Identity.Realm,
			&h.Identity.SSSDOnline, &h.Identity.CheckedAt,
			&windowUntil, &windowReason, &windowBy, &windowFrom,
			&refusalCode, &refusalAt, &refusalDetail,
			&h.Capabilities, &identityPayload, &identityObservedAt); err != nil {
			return nil, err
		}
		if h.Identity.Enrolled {
			h.Identity.OfflineVerdict = judgeFromFragment(h.Identity.SSSDOnline,
				identityPayload, identityObservedAt)
		}
		// The verdict on the configuration is judged here, against the
		// schema this panel ships with: a host that reported a schema is
		// on the legacy configuration when it runs on no file (zero) or on
		// a file older than the current schema. A host that reported none
		// gets no verdict.
		if h.ConfigSchemaVersion != nil {
			legacy := *h.ConfigSchemaVersion < agentconfig.SchemaVersion
			h.ConfigLegacy = &legacy
		}
		// An empty tag list is a fact about the host and is sent as one,
		// not as a missing field.
		if h.Tags == nil {
			h.Tags = []string{}
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
		// A refusal is reported with its moment or not at all: a code
		// without a time would be a fault nobody can place.
		if refusalCode != "" && refusalAt != nil {
			h.LastConnectionRefusal = &ConnectionRefusal{Code: refusalCode, At: *refusalAt, Detail: refusalDetail}
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

// AgentReport is what an agent says about itself in its Hello beyond the
// version and the boot: the sources it was built from, the protocols it
// speaks and the configuration it runs on. An agent that announces no
// protocol range predates the report and sends none.
type AgentReport struct {
	BuildCommit         string
	ProtocolMin         int
	ProtocolMax         int
	ConfigFingerprint   string
	ConfigSchemaVersion int
}

// RecordAgentReport writes what the agent reported about itself at its
// Hello. A nil report clears the columns: the agent that connected says
// nothing about its build, and what the previous one said is not a fact
// about this one - a host downgraded to an agent from before the report
// is a host of an unknown build, not of the last known one.
func (s *Store) RecordAgentReport(ctx context.Context, hostID string, report *AgentReport) error {
	const query = `
		update hosts
		   set agent_build_commit    = $2,
		       agent_protocol_min    = $3,
		       agent_protocol_max    = $4,
		       config_fingerprint    = $5,
		       config_schema_version = $6,
		       updated_at            = now()
		 where id = $1`
	if report == nil {
		_, err := s.pool.Exec(ctx, query, hostID, nil, nil, nil, nil, nil)
		return err
	}
	var commit, fingerprint *string
	if report.BuildCommit != "" {
		commit = &report.BuildCommit
	}
	if report.ConfigFingerprint != "" {
		fingerprint = &report.ConfigFingerprint
	}
	_, err := s.pool.Exec(ctx, query, hostID, commit, report.ProtocolMin, report.ProtocolMax,
		fingerprint, report.ConfigSchemaVersion)
	return err
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

// Rename records the name the host reports for itself. The hosts table
// keeps the name from enrollment until the host says otherwise: the name
// a host answers to is a fact of the host, not of the panel. The previous
// name comes back so the change can be recorded; a report of the same name
// changes nothing and returns changed false.
func (s *Store) Rename(ctx context.Context, hostID, hostname string) (previous string, changed bool, err error) {
	if hostname == "" {
		return "", false, nil
	}
	const query = `
		update hosts as h
		   set hostname   = $2,
		       updated_at = now()
		  from hosts as prior
		 where h.id = $1
		   and prior.id = h.id
		   and h.hostname <> $2
		returning prior.hostname`
	err = s.pool.QueryRow(ctx, query, hostID, hostname).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("renaming the host: %w", err)
	}
	return previous, true, nil
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

// MaxTags bounds the tags of one host. More than that is not a description
// anybody reads; it is a second inventory kept by hand.
const MaxTags = 32

// ErrInvalidTags means a tag list the panel does not accept; the message
// names the tag.
var ErrInvalidTags = errors.New("invalid tags")

// NormalizeTags checks a tag list and returns it sorted and without
// repeats. A tag is 'key' or 'key=value' in the shape selector.TagPattern
// describes; the same tag twice is one tag, and the order is not a fact
// about the host.
func NormalizeTags(tags []string) ([]string, error) {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if len(tag) > 128 {
			return nil, fmt.Errorf("%w: %q is longer than 128 characters", ErrInvalidTags, tag)
		}
		if !selector.TagPattern.MatchString(tag) {
			return nil, fmt.Errorf("%w: %q is not a tag (key or key=value, lower-case key)", ErrInvalidTags, tag)
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		normalized = append(normalized, tag)
	}
	if len(normalized) > MaxTags {
		return nil, fmt.Errorf("%w: a host carries at most %d tags", ErrInvalidTags, MaxTags)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// The release channels a host may follow. The list is the same one the
// host table constrains.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ErrInvalidChannel means a channel the panel does not have.
var ErrInvalidChannel = errors.New("invalid release channel")

// NormalizeChannel checks a channel name. An empty name is refused rather
// than read as the default: assigning a host to a channel is an explicit
// decision, and "no channel" is not one.
func NormalizeChannel(channel string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case ChannelStable:
		return ChannelStable, nil
	case ChannelBeta:
		return ChannelBeta, nil
	}
	return "", fmt.Errorf("%w: %q is not a channel (stable or beta)", ErrInvalidChannel, channel)
}

// SetChannel moves a host to a release channel.
func (s *Store) SetChannel(ctx context.Context, hostID, channel string) (*Host, error) {
	normalized, err := NormalizeChannel(channel)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx,
		`update hosts set release_channel = $2, updated_at = now() where id = $1`, hostID, normalized)
	if err != nil {
		return nil, fmt.Errorf("setting the release channel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// SetTags replaces the tags of a host. The list is the whole list: a tag
// left out is a tag removed, so the caller sends what it read plus the
// change, and two operators editing at once see the second write win in
// full rather than a merge nobody asked for.
func (s *Store) SetTags(ctx context.Context, hostID string, tags []string) (*Host, error) {
	if tags == nil {
		tags = []string{}
	}
	tag, err := s.pool.Exec(ctx, `update hosts set tags = $2, updated_at = now() where id = $1`, hostID, tags)
	if err != nil {
		return nil, fmt.Errorf("setting the tags: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// MaxOwnerLength bounds the owner of a host. The owner is a name or a team
// the operator types, not a paragraph; a longer value is a note in the
// wrong field.
const MaxOwnerLength = 128

// ErrInvalidOwner means an owner the panel does not accept; the message
// says what is wrong with it.
var ErrInvalidOwner = errors.New("invalid owner")

// NormalizeOwner checks an owner. An empty owner is allowed and means
// nobody: clearing the field is how a host is handed back to the pool.
// Control characters are refused, because the owner is printed in tables
// and in the trail, where a line break would forge a second row.
func NormalizeOwner(owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	if len(owner) > MaxOwnerLength {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidOwner, MaxOwnerLength)
	}
	for _, r := range owner {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("%w: control characters are not allowed", ErrInvalidOwner)
		}
	}
	return owner, nil
}

// SetOwner records who answers for a host. An empty owner clears the field.
func (s *Store) SetOwner(ctx context.Context, hostID, owner string) (*Host, error) {
	normalized, err := NormalizeOwner(owner)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx,
		`update hosts set owner = nullif($2, ''), updated_at = now() where id = $1`, hostID, normalized)
	if err != nil {
		return nil, fmt.Errorf("setting the owner: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// MaxFailureDomainLength bounds the failure domain of a host. It is a
// name - a rack, a zone, a cluster - not a description of the topology.
const MaxFailureDomainLength = 128

// ErrInvalidFailureDomain means a failure domain the panel does not
// accept; the message says what is wrong with it.
var ErrInvalidFailureDomain = errors.New("invalid failure domain")

// NormalizeFailureDomain checks a failure domain. An empty domain is
// allowed and means nobody placed the host: clearing the field takes the
// host out from under the domain budgets rather than putting it in a
// domain of the unplaced. Control characters are refused, because the
// domain is printed in tables and becomes part of a budget key.
func NormalizeFailureDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if len(domain) > MaxFailureDomainLength {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidFailureDomain, MaxFailureDomainLength)
	}
	for _, r := range domain {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("%w: control characters are not allowed", ErrInvalidFailureDomain)
		}
	}
	return domain, nil
}

// SetFailureDomain records what the host goes down with. An empty domain
// clears the field.
func (s *Store) SetFailureDomain(ctx context.Context, hostID, domain string) (*Host, error) {
	normalized, err := NormalizeFailureDomain(domain)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx,
		`update hosts set failure_domain = nullif($2, ''), updated_at = now() where id = $1`, hostID, normalized)
	if err != nil {
		return nil, fmt.Errorf("setting the failure domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// ErrInvalidAddress means a management address that is neither an IP
// address nor a host name.
var ErrInvalidAddress = errors.New("invalid management address")

// hostnamePattern is an RFC 1123 name: lower-case labels of letters,
// digits and inner hyphens, joined by dots.
var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// NormalizeManagementAddress checks an address an operator types by hand.
// An IP address comes back in its canonical spelling and a name in lower
// case, so the same address typed twice is stored once. An empty address
// is allowed: it is the request to forget the manual value.
func NormalizeManagementAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", nil
	}
	if ip := net.ParseIP(address); ip != nil {
		return ip.String(), nil
	}
	name := strings.ToLower(strings.TrimSuffix(address, "."))
	if len(name) > 253 || !hostnamePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q is neither an IP address nor a host name", ErrInvalidAddress, address)
	}
	return name, nil
}

// SetManualManagementAddress records the address an operator chose for
// reaching the host. The source is then 'manual', which the observations
// of the gateway and of the agent do not overwrite: the operator said how
// this host is reached, and a connection from behind NAT knows less than
// they do. An empty address takes the manual value away - only that one:
// an observed address is a fact and stays - so the next session or agent
// report fills the field again.
func (s *Store) SetManualManagementAddress(ctx context.Context, hostID, address string) (*Host, error) {
	normalized, err := NormalizeManagementAddress(address)
	if err != nil {
		return nil, err
	}
	var (
		query string
		args  []any
	)
	if normalized == "" {
		query = `
			update hosts
			   set management_address = case when management_address_source = 'manual'
			                                 then null else management_address end,
			       management_address_source = case when management_address_source = 'manual'
			                                        then null else management_address_source end,
			       management_address_observed_at = case when management_address_source = 'manual'
			                                             then null else management_address_observed_at end,
			       updated_at = now()
			 where id = $1`
		args = []any{hostID}
	} else {
		query = `
			update hosts
			   set management_address             = $2,
			       management_address_source       = 'manual',
			       management_address_observed_at  = now(),
			       updated_at                      = now()
			 where id = $1`
		args = []any{hostID, normalized}
	}
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("setting the management address: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// ApplyEnrollmentFacts records what the installation order said about the
// host: its owner and its tags. The order is written by the operator who
// knows the machine before it exists in the panel, so the facts land in the
// same transaction as the host row. The tags are added to the ones already
// there and the owner is set only when the order names one: a token can
// bring a known machine back, and what an operator recorded about it
// meanwhile is not the token's to erase.
func (s *Store) ApplyEnrollmentFacts(ctx context.Context, tx pgx.Tx, hostID, owner string, tags []string) error {
	if owner == "" && len(tags) == 0 {
		return nil
	}
	if tags == nil {
		tags = []string{}
	}
	const query = `
		update hosts
		   set owner      = coalesce(nullif($2, ''), owner),
		       tags       = (select coalesce(array_agg(distinct tag order by tag), '{}')
		                       from unnest(tags || $3::text[]) as tag),
		       updated_at = now()
		 where id = $1::uuid`
	tag, err := tx.Exec(ctx, query, hostID, owner, tags)
	if err != nil {
		return fmt.Errorf("applying the facts of the order: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SystemHistoryLimit is how many (kernel, distribution) pairs the panel
// keeps per host. A host changes its kernel a few times a year; twenty
// pairs reach back further than anybody asks, and a bounded row count
// keeps the fleet's history from growing with every reboot.
const SystemHistoryLimit = 20

// SystemHistoryEntry is one platform the panel has seen a host on: a
// kernel and a distribution release, with the span it was seen over.
type SystemHistoryEntry struct {
	Kernel              string    `json:"kernel"`
	Distribution        string    `json:"distribution"`
	DistributionVersion string    `json:"distribution_version"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
}

// RecordSystemHistory notes that the host was seen on this kernel and
// release at the given moment. A pair seen before moves its last_seen;
// a new one gets a row, and the oldest rows beyond the limit go.
//
// It returns whether the pair was new: the gateway logs a host that came
// up on something it had not seen before, and stays quiet otherwise.
func (s *Store) RecordSystemHistory(ctx context.Context, hostID string, entry SystemHistoryEntry) (bool, error) {
	if entry.Kernel == "" && entry.Distribution == "" {
		// A report that names neither says nothing about the platform.
		return false, nil
	}
	seen := entry.LastSeenAt
	if seen.IsZero() {
		seen = time.Now().UTC()
	}
	const upsert = `
		insert into host_system_history
			(host_id, kernel, distribution, distribution_version, first_seen_at, last_seen_at)
		values ($1, $2, $3, $4, $5, $5)
		on conflict (host_id, kernel, distribution, distribution_version) do update
		   set last_seen_at  = greatest(host_system_history.last_seen_at, excluded.last_seen_at),
		       first_seen_at = least(host_system_history.first_seen_at, excluded.first_seen_at)
		returning (xmax = 0)`
	var created bool
	if err := s.pool.QueryRow(ctx, upsert, hostID, entry.Kernel, entry.Distribution,
		entry.DistributionVersion, seen).Scan(&created); err != nil {
		return false, fmt.Errorf("recording the platform history: %w", err)
	}
	if !created {
		return false, nil
	}
	// The cap holds at every insert rather than until a sweep: the rows
	// beyond the newest twenty go now.
	const prune = `
		delete from host_system_history
		 where host_id = $1
		   and (kernel, distribution, distribution_version) in (
		       select kernel, distribution, distribution_version
		         from host_system_history
		        where host_id = $1
		        order by last_seen_at desc, first_seen_at desc
		       offset $2)`
	if _, err := s.pool.Exec(ctx, prune, hostID, SystemHistoryLimit); err != nil {
		return true, fmt.Errorf("pruning the platform history: %w", err)
	}
	return true, nil
}

// SystemHistory lists the platforms the host was seen on, the most
// recently seen first.
func (s *Store) SystemHistory(ctx context.Context, hostID string) ([]SystemHistoryEntry, error) {
	const query = `
		select kernel, distribution, distribution_version, first_seen_at, last_seen_at
		  from host_system_history
		 where host_id = $1
		 order by last_seen_at desc, first_seen_at desc`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []SystemHistoryEntry{}
	for rows.Next() {
		var entry SystemHistoryEntry
		if err := rows.Scan(&entry.Kernel, &entry.Distribution, &entry.DistributionVersion,
			&entry.FirstSeenAt, &entry.LastSeenAt); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}
