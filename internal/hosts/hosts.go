// Package hosts stores the identity and state of hosts.
package hosts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// The names of the adapters and the requirements of operations.
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
	// Writing the network configuration. Reading works everywhere iproute2 is, so
	// the module alone does not yet say that anything can be changed here.
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
			// The adapter is present but silent about its features: the host decides at
			// execution time, as it did before the registry was introduced.
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
		// Writing the network requires a mechanism that persists the change and
		// allows rolling it back.
		value, known := c.FeatureState(CapNetwork, "write")
		if value {
			return true
		}
		// The adapter is present but silent about its features: the host decides at
		// execution time, as it did before the registry was introduced.
		return !known && c.Available(CapNetwork)
	default:
		return c.Available(requirement)
	}
}

// Health is the minimal set of signals from a heartbeat.
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
	// PlacementChangedAt is when an operator last moved the host to another site
	// or environment.
	PlacementChangedAt *time.Time `json:"placement_changed_at,omitempty"`
	Owner              string     `json:"owner,omitempty"`
	// TeamID is the team the host belongs to and TeamName what that team is
	// called.
	TeamID   string `json:"team_id,omitempty"`
	TeamName string `json:"team_name,omitempty"`
	// FailureDomain is what the host goes down with - a rack, an availability
	// zone, a cluster whose members keep a service alive - recorded by an
	// operator, and keyed on by the budgets that keep a campaign from taking a.
	FailureDomain  string `json:"failure_domain,omitempty"`
	LifecycleState string `json:"lifecycle_state"`
	// LifecycleReason and LifecycleChangedAt are the decision behind a state
	// other than active: who cut the host off and why is part of the host, not a
	// line to dig out of the audit trail.
	LifecycleReason    string     `json:"lifecycle_reason,omitempty"`
	LifecycleChangedAt *time.Time `json:"lifecycle_changed_at,omitempty"`
	// LifecycleChangedBy is who took the decision: an operator's subject,
	// or the agent or the panel when the state changed by rule.
	LifecycleChangedBy string     `json:"lifecycle_changed_by,omitempty"`
	OSFamily           string     `json:"os_family,omitempty"`
	OSDistribution     string     `json:"os_distribution,omitempty"`
	OSVersion          string     `json:"os_version,omitempty"`
	Architecture       string     `json:"architecture,omitempty"`
	AgentVersion       string     `json:"agent_version,omitempty"`
	ConnectionState    string     `json:"connection_state"`
	LastSeenAt         *time.Time `json:"last_seen_at,omitempty"`
	BootID             string     `json:"boot_id,omitempty"`
	// What the agent reported about itself at its last Hello beyond the version:
	// the commit it was built from, the protocols it speaks, and the
	// configuration it runs on.
	AgentBuildCommit string `json:"agent_build_commit,omitempty"`
	AgentProtocolMin *int   `json:"agent_protocol_min,omitempty"`
	AgentProtocolMax *int   `json:"agent_protocol_max,omitempty"`
	// ConfigFingerprint digests the effective agent. yaml; absent also for a host
	// on the environment variables of the old flow, which has no file.
	ConfigFingerprint   string `json:"config_fingerprint,omitempty"`
	ConfigSchemaVersion *int   `json:"config_schema_version,omitempty"`
	ConfigLegacy        *bool  `json:"config_legacy,omitempty"`
	// What the host's root helper does with a capability the panel signed:
	// observe, prefer or enforce. Empty for a helper that has not said, which is
	// not the same as observe - an agent from before the capability says nothing.
	HelperCapabilityMode      string `json:"helper_capability_mode,omitempty"`
	HelperCapabilitySupported *bool  `json:"helper_capability_supported,omitempty"`
	// Tags are what operators recorded about the host: 'key' or 'key=value'.
	Tags []string `json:"tags"`
	// ReleaseChannel says which agent releases the host follows: stable or beta.
	ReleaseChannel string `json:"release_channel"`
	// Notes are what an operator wrote about the host that fits no other field:
	// the ticket, the quirk, whom to call.
	Notes string `json:"notes,omitempty"`
	// Empty fields mean an undetermined state, not zero.
	RebootRequired           *bool  `json:"reboot_required"`
	FailedUnits              *int   `json:"failed_units"`
	PendingUpdates           *int   `json:"pending_updates"`
	PendingSecurityUpdates   *int   `json:"pending_security_updates"`
	CurrentInventoryRevision string `json:"current_inventory_revision,omitempty"`
	PackageDatabaseBroken    bool   `json:"package_database_broken"`
	// The management address and where it came from.
	ManagementAddress           string     `json:"management_address,omitempty"`
	ManagementAddressSource     string     `json:"management_address_source,omitempty"`
	ManagementAddressObservedAt *time.Time `json:"management_address_observed_at,omitempty"`
	// Maintenance is the maintenance window. An empty field means a host
	// outside a window, not a window of zero length.
	Maintenance *MaintenanceWindow `json:"maintenance,omitempty"`
	// LastConnectionRefusal is why the gateway last turned the host away since
	// its last session.
	LastConnectionRefusal *ConnectionRefusal `json:"last_connection_refusal,omitempty"`
	// RelayIdentity says how the host's last session through a relay was
	// identified: end_to_end when the host's own signature on the envelope
	// verified, attested when the relay named the certificate and the gateway.
	RelayIdentity string       `json:"relay_identity,omitempty"`
	Identity      HostIdentity `json:"identity"`
	EnrolledAt    time.Time    `json:"enrolled_at"`
	Capabilities  Capabilities `json:"capabilities"`
}

// ConnectionRefusal is the reason the gateway would not open a session for
// the host, as the host page and the fleet list show it.
type ConnectionRefusal struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
	// Detail is what the gateway saw - the serial and the validity of the
	// certificate, or the state of the host - for the operator who wants more
	// than the code.
	Detail string `json:"detail,omitempty"`
}

// The refusal codes of the gateway.
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
	// RefusalRelayIdentityMissing is a session through a relay that did not
	// attest which certificate the host presented, refused because the
	// installation requires the attestation (FLOTESTRO_RELAY_IDENTITY=enforce).
	RefusalRelayIdentityMissing = "relay_identity_missing"
	// RefusalRelayIdentityInvalid is an attestation the gateway could not read: a
	// fingerprint that is not one, or a serial that does not belong to the
	// fingerprint.
	RefusalRelayIdentityInvalid = "relay_identity_invalid"
	// RefusalRelayScopeMismatch is a host attested by a relay of another
	// site or environment: a relay mediates for its own scope alone.
	RefusalRelayScopeMismatch = "relay_scope_mismatch"
	// RefusalRelayEnvelopeInvalid is a relayed message whose identity envelope
	// the gateway could not accept for a reason other than the three below:
	// another schema, a relay other than the one that forwarded it, a host other.
	RefusalRelayEnvelopeInvalid = "relay_envelope_invalid"
	// RefusalRelayBodyHashMismatch is a payload other than the one the host
	// signed: changed on the way, or carrying a field this panel does not know,
	// which the fleet rule - panel before agents - rules out.
	RefusalRelayBodyHashMismatch = "relay_body_hash_mismatch"
	// RefusalRelaySequenceReplayed is a signed message carried a second
	// time under a sequence the session already accepted.
	RefusalRelaySequenceReplayed = "relay_sequence_replayed"
	// RefusalRelayHostSignatureInvalid is an envelope whose signature does
	// not verify under the key of the certificate it names.
	RefusalRelayHostSignatureInvalid = "relay_host_signature_invalid"
	// RefusalBlockedUpgradeRequired is a host whose agent predates a proof the
	// installation requires: behind a relay under
	// FLOTESTRO_RELAY_IDENTITY=enforce, an agent that does not sign the envelope.
	RefusalBlockedUpgradeRequired = "blocked_upgrade_required"
)

// The strength of the identity behind a host's session, as the host record
// shows it.
const (
	// RelayIdentityAttested is a session through a relay that named the
	// certificate of the host, and the gateway checked that certificate against
	// the record as it would in a direct handshake.
	RelayIdentityAttested = "attested"
	// RelayIdentityWeak is a session through a relay that named the host alone:
	// the relay vouches for it, and the gateway could check nothing about the
	// certificate.
	RelayIdentityWeak = "weak"
	// RelayIdentityEndToEnd is a session through a relay in which the host itself
	// signed the envelope of every message with its key, and the gateway verified
	// the signature against the certificate on record.
	RelayIdentityEndToEnd = "end_to_end"
)

// AuthStrength is the strength of a session as agent_sessions records it:
// end_to_end for a verified envelope, relay_only for a session that rests on
// the relay's attestation or word, empty for a direct connection.
func AuthStrength(relayIdentity string) string {
	switch relayIdentity {
	case RelayIdentityEndToEnd:
		return "end_to_end"
	case RelayIdentityAttested, RelayIdentityWeak:
		return "relay_only"
	}
	return ""
}

// MaintenanceWindow describes a host's maintenance window.
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
	// outage, from the facts the host reported.
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
// machine_id, so enrolling the same machine again does not create a duplicate.
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

// The host lifecycle states. Only an active host gets tasks, sessions, secrets
// and renewals.
const (
	StateActive      = "active"
	StateQuarantined = "quarantined"
	// StateRecovery is the host between an identity recovery order and the first
	// session of the new certificate.
	StateRecovery = "recovery"
	// StateRetiring is the host in the decommission handshake: the final
	// task went out and the host is finishing what it started.
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

// RecoveryOverlap is how long the certificate replaced by a recovery may still
// open a session.
const RecoveryOverlap = 24 * time.Hour

// RetiredMachineRetention is how long the machine identifier of a retired
// host is refused for a "new host" token.
const RetiredMachineRetention = 30 * 24 * time.Hour

// Active says whether in this state the panel may order the host anything.
func Active(state string) bool { return state == StateActive }

// Connectable says whether a certificate of a host in this state may open a
// session at the given moment.
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

// LapseRecoveries returns to active the hosts whose recovery has nothing left
// to wait for: no pending recovery order, and no certificate issued since the
// order.
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
// until when its machine identifier is held back from "new host" tokens.
func (s *Store) RetiredMachine(ctx context.Context, tx pgx.Tx, hostID string) (retired bool, until time.Time, err error) {
	// A host retired before the hold existed gets the same retention from its
	// retirement: the rule is about the machine, not about the release that
	// introduced the column.
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

// ReleaseMachineID frees the machine identifier of a retired host, so that the
// same machine can enter the fleet as a new host once the retention has
// passed.
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

// RevokeSupersededCertificates revokes the certificates of a host older than
// the one it has just presented.
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

// HasLiveCertificate says whether the host holds a certificate that is neither
// revoked nor expired.
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
	fingerprint []byte, notBefore, notAfter time.Time, issuerSubject, issuerSerial, issuerID string) error {
	const query = `
		insert into agent_certificates
			(id, host_id, serial, fingerprint_sha256, subject_common_name, not_before, not_after,
			 issuer_subject, issuer_serial, issuer_id)
		values ($1, $2, $3, $4, $5, $6, $7, nullif($8, ''), nullif($9, ''), nullif($10, '')::uuid)`
	_, err := tx.Exec(ctx, query, uuid.NewString(), hostID, serial, fingerprint, commonName,
		notBefore, notAfter, issuerSubject, issuerSerial, issuerID)
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
	// NotBefore and NotAfter are the validity as issued.
	NotBefore time.Time
	NotAfter  time.Time
	// Fingerprint is the SHA-256 of the certificate as issued, and PublicKeyDER
	// its SubjectPublicKeyInfo.
	Fingerprint  []byte
	PublicKeyDER []byte
}

// LookupCertificate checks whether the certificate is known and not revoked
// and whether the host is not in quarantine.
func (s *Store) LookupCertificate(ctx context.Context, fingerprint []byte) (CertificateStatus, error) {
	const query = `
		select c.host_id, h.lifecycle_state, h.lifecycle_changed_at, c.revoked_at is not null, c.serial,
		       c.not_before, c.not_after
		from agent_certificates c
		join hosts h on h.id = c.host_id
		where c.fingerprint_sha256 = $1`
	var status CertificateStatus
	err := s.pool.QueryRow(ctx, query, fingerprint).
		Scan(&status.HostID, &status.LifecycleState, &status.LifecycleChangedAt, &status.Revoked, &status.Serial,
			&status.NotBefore, &status.NotAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateStatus{}, nil
	}
	if err != nil {
		return CertificateStatus{}, err
	}
	status.Known = true
	return status, nil
}

// LookupCertificateBySerial reads the record of a certificate the gateway
// never saw itself: the envelope of a relayed session names it by serial.
func (s *Store) LookupCertificateBySerial(ctx context.Context, serial string) (CertificateStatus, error) {
	const query = `
		select c.host_id, h.lifecycle_state, h.lifecycle_changed_at, c.revoked_at is not null, c.serial,
		       c.not_before, c.not_after, c.fingerprint_sha256, c.public_key_der
		from agent_certificates c
		join hosts h on h.id = c.host_id
		where c.serial = $1`
	var status CertificateStatus
	err := s.pool.QueryRow(ctx, query, serial).
		Scan(&status.HostID, &status.LifecycleState, &status.LifecycleChangedAt, &status.Revoked, &status.Serial,
			&status.NotBefore, &status.NotAfter, &status.Fingerprint, &status.PublicKeyDER)
	if errors.Is(err, pgx.ErrNoRows) {
		return CertificateStatus{}, nil
	}
	if err != nil {
		return CertificateStatus{}, err
	}
	status.Known = true
	return status, nil
}

// Executor is what a statement runs on: the pool or a transaction.
type Executor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// RecordCertificatePublicKey writes the public key of an issued certificate on
// its record, once: a key already on record is not replaced, because the
// record is what the envelopes of the host are checked against and a.
func (s *Store) RecordCertificatePublicKey(ctx context.Context, db Executor, serial string, der []byte) error {
	if db == nil {
		db = s.pool
	}
	_, err := db.Exec(ctx, `
		update agent_certificates set public_key_der = $2
		 where serial = $1 and public_key_der is null`, serial, der)
	if err != nil {
		return fmt.Errorf("recording the public key of certificate %s: %w", serial, err)
	}
	return nil
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
	// The refusal goes with the session that opens: whatever kept the host out is
	// over, and a reason left standing would send the operator after a fault the
	// host no longer has.
	if _, err := tx.Exec(ctx, hostQuery, hostID, agentVersion, bootID); err != nil {
		return fmt.Errorf("updating the host: %w", err)
	}

	// The registry is replaced in full: an adapter the host no longer reports has
	// disappeared from the host and must not stay in the database as a stale
	// truth.
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
// last_seen_at.
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

// RecordRelayIdentity writes down how the session that has just opened
// identified the host: end_to_end, attested or weak through a relay, empty for
// a direct connection.
func (s *Store) RecordRelayIdentity(ctx context.Context, hostID, strength string) error {
	_, err := s.pool.Exec(ctx,
		`update hosts set relay_identity = nullif($2, ''), updated_at = now() where id = $1`,
		hostID, strength)
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
	// Search keeps the hosts with the text somewhere in the hostname, the
	// management address, the machine identifier or the owner.
	Search         string
	LifecycleState string
	Owner          string
	// Maintenance keeps the hosts inside a maintenance window (true) or
	// outside one (false). Nil does not narrow.
	Maintenance *bool
	// RebootRequired keeps the hosts that need a reboot (true) or the ones that
	// reported they do not (false).
	RebootRequired *bool
	// SecurityUpdates keeps the hosts with a security update waiting (true) or
	// with a count of none (false); unknown counts are left out of both, for the
	// same reason.
	SecurityUpdates *bool
	// FailedUnits keeps the hosts with at least one failed unit (true) or with a
	// count of none (false).
	FailedUnits *bool
	// PackageDatabaseBroken keeps the hosts whose package database the last
	// operation found broken (true) or sound (false).
	PackageDatabaseBroken *bool
	// SSSDOffline keeps the domain-joined hosts whose SSSD reported itself
	// offline (true) or online (false).
	SSSDOffline *bool
	// AgentBehind keeps the hosts whose agent is older (true) or as new (false)
	// as the newest version any visible host reports - the same yardstick the
	// dashboard's "agents behind" tile counts by, since the panel has no release.
	AgentBehind *bool
	// Relay keeps the hosts whose open session the named relay attested.
	Relay string
	// FailureDomain keeps the hosts an operator placed in the named domain.
	FailureDomain string
	// Team keeps the hosts of one team, named by its identifier.
	Team           string
	TeamUnassigned bool
	// Capability keeps the hosts whose registry has the named adapter
	// available; 'packages.apt', not 'packages'.
	Capability string
	// Tags keeps the hosts carrying every one of the given tags.
	Tags []string
	// Channel keeps the hosts on the given release channel.
	Channel string
	// ConnectionRefusal keeps the hosts the gateway last turned away for the
	// given reason, so the dashboard counter leads to the hosts it counted.
	ConnectionRefusal string
	// IDs keeps the named hosts. Nil does not narrow; an empty list keeps
	// nothing, because a list of nobody names nobody.
	IDs []string
	// Expression is a selector already expanded of its group references; it is
	// compiled into the same query as the other filters, so a campaign's targets
	// and the host list answer the same question.
	Expression *selector.Expression
	// Scopes narrow the result to what the caller may read.
	Scopes []authz.Scope
	Limit  int
	// Sort is the order of a paged list; the zero value is the hostname,
	// ascending.
	Sort Sort
}

// ErrInvalidSort means a sort a caller asked for that names no column of
// the list, or a direction that is neither asc nor desc.
var ErrInvalidSort = errors.New("invalid sort")

// Sort is the order of the host list: a column of the whitelist below and a
// direction.
type Sort struct {
	Column     string
	Descending bool
}

// ParseSort reads a sort as the API carries it: column, column:asc or
// column:desc. An empty value is the default order.
func ParseSort(value string) (Sort, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Sort{}, nil
	}
	column, direction, _ := strings.Cut(value, ":")
	if _, ok := sortColumns[column]; !ok {
		return Sort{}, fmt.Errorf("%w: %q is not a column of the host list", ErrInvalidSort, column)
	}
	switch direction {
	case "", "asc":
		return Sort{Column: column}, nil
	case "desc":
		return Sort{Column: column, Descending: true}, nil
	}
	return Sort{}, fmt.Errorf("%w: the direction must be asc or desc, not %q", ErrInvalidSort, direction)
}

// column names the sorted column, the default made explicit.
func (s Sort) column() string {
	if s.Column == "" {
		return "hostname"
	}
	return s.Column
}

// String renders the sort the way ParseSort reads it; the default order
// renders as "hostname" so a cursor carries the same spelling either way.
func (s Sort) String() string {
	if s.Descending {
		return s.column() + ":desc"
	}
	return s.column()
}

// sortColumn is one column the list can be ordered by: its SQL expression,
// the cursor's type, how a row renders its value and which values are valid.
type sortColumn struct {
	expression string
	kind       string
	key        func(Host) string
	valid      func(string) bool
}

// sortColumns are the columns the host list can be ordered by.
var sortColumns = map[string]sortColumn{
	"hostname": {"h.hostname", "text", func(h Host) string { return h.Hostname }, anyText},
	"site":     {"h.site", "text", func(h Host) string { return h.Site }, anyText},
	"environment": {
		"h.environment", "text", func(h Host) string { return h.Environment }, anyText,
	},
	"owner": {"coalesce(h.owner, '')", "text", func(h Host) string { return h.Owner }, anyText},
	"lifecycle_state": {
		"h.lifecycle_state", "text", func(h Host) string { return h.LifecycleState }, anyText,
	},
	"connection_state": {
		"h.connection_state", "text", func(h Host) string { return h.ConnectionState }, anyText,
	},
	"agent_version": {
		"coalesce(" + versionParts("h") + ", '{}'::int[])", "int[]",
		func(h Host) string { return versionKey(h.AgentVersion) }, validVersionKey,
	},
	"last_seen_at": {
		"coalesce(h.last_seen_at, '-infinity'::timestamptz)", "timestamptz",
		func(h Host) string { return timeKey(h.LastSeenAt) }, validTimeKey,
	},
	"pending_updates": {
		"coalesce(h.pending_updates, -1)", "integer",
		func(h Host) string { return countKey(h.PendingUpdates) }, validCountKey,
	},
	"pending_security_updates": {
		"coalesce(h.pending_security_updates, -1)", "integer",
		func(h Host) string { return countKey(h.PendingSecurityUpdates) }, validCountKey,
	},
	"failed_units": {
		"coalesce(h.failed_units, -1)", "integer",
		func(h Host) string { return countKey(h.FailedUnits) }, validCountKey,
	},
}

// SortColumns lists the columns the list can be ordered by, for the API's
// description of itself.
func SortColumns() []string {
	names := make([]string, 0, len(sortColumns))
	for name := range sortColumns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The cursor value of each kind of key, rendered from the row the way the
// database renders the expression, and checked on the way back so that a token
// somebody edited fails as an invalid cursor rather than as a query the.

func anyText(string) bool { return true }

// timeKey renders a timestamp the way the expression coalesces it: the
// earliest possible moment when the host has never been seen.
func timeKey(at *time.Time) string {
	if at == nil {
		return "-infinity"
	}
	return paging.FormatTime(*at)
}

func validTimeKey(value string) bool {
	if value == "-infinity" {
		return true
	}
	_, err := paging.ParseTime(value)
	return err == nil
}

// countKey renders a count the way the expression coalesces it: -1 for a
// count the host has not reported.
func countKey(count *int) string {
	if count == nil {
		return "-1"
	}
	return strconv.Itoa(*count)
}

func validCountKey(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

// versionPattern is the Go spelling of the pattern versionParts reads the
// version with: the two must agree, or the cursor names a key the database
// never computed.
var versionPattern = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// versionKey renders an agent version as the array literal the database
// compares: {0,49,0} for 0.
func versionKey(version string) string {
	match := versionPattern.FindStringSubmatch(version)
	if match == nil {
		return "{}"
	}
	return "{" + strings.ReplaceAll(match[1], ".", ",") + "}"
}

var versionKeyPattern = regexp.MustCompile(`^\{(\d{1,10}(,\d{1,10})*)?\}$`)

func validVersionKey(value string) bool {
	return versionKeyPattern.MatchString(value)
}

// conditions renders the filter as SQL over the alias h.
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
	if f.FailedUnits != nil {
		// The count is null for a host that has not reported; the
		// comparison leaves it out of both answers.
		if *f.FailedUnits {
			conditions = append(conditions, "h.failed_units > 0")
		} else {
			conditions = append(conditions, "h.failed_units = 0")
		}
	}
	if f.PackageDatabaseBroken != nil {
		if *f.PackageDatabaseBroken {
			conditions = append(conditions, "(h.package_database_broken and h.lifecycle_state <> 'retired')")
		} else {
			conditions = append(conditions, "not h.package_database_broken")
		}
	}
	if f.SSSDOffline != nil {
		// Only a host in a domain has an SSSD to be offline; the column is
		// null until the host has said either way.
		if *f.SSSDOffline {
			conditions = append(conditions,
				"(h.identity_enrolled and h.identity_sssd_online = false and h.lifecycle_state <> 'retired')")
		} else {
			conditions = append(conditions, "(h.identity_enrolled and h.identity_sssd_online = true)")
		}
	}
	if f.AgentBehind != nil {
		// The version is ordered numerically part by part, the way the dashboard
		// orders it, and the newest one is taken over the hosts the caller may see:
		// a scoped operator's fleet has a newest of its own, and the tile they.
		newest := "select max(" + versionParts("n") + ") from hosts n" +
			" where n.lifecycle_state <> 'retired' and n.agent_version ~ '^v?\\d+(\\.\\d+)*'"
		if f.Scopes != nil {
			if condition, extra := ScopeSQL(f.Scopes, "n.site", "n.environment", "n.team_id", len(args)); condition != "" {
				newest += " and " + condition
				args = append(args, extra...)
			}
		}
		comparison := "<"
		if !*f.AgentBehind {
			comparison = "="
		}
		conditions = append(conditions,
			"(h.lifecycle_state <> 'retired' and h.agent_version ~ '^v?\\d+(\\.\\d+)*'"+
				" and "+versionParts("h")+" "+comparison+" ("+newest+"))")
	}
	if f.Relay != "" {
		// The identifier travels as text and is cast in the query; the
		// handler has checked that it is one.
		args = append(args, f.Relay)
		conditions = append(conditions, fmt.Sprintf(
			"exists (select 1 from agent_sessions s"+
				" where s.host_id = h.id and s.ended_at is null and s.relay_id = $%d::uuid)", len(args)))
	}
	add("h.failure_domain", f.FailureDomain)
	if f.Team != "" {
		// The identifier travels as text and is cast in the query; the
		// handler has checked that it is one.
		args = append(args, f.Team)
		conditions = append(conditions, fmt.Sprintf("h.team_id = $%d::uuid", len(args)))
	}
	if f.TeamUnassigned {
		conditions = append(conditions, "h.team_id is null")
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
		// The narrowing rule lives next to the authorisation, so that a list cannot
		// show what a direct read would refuse.
		if condition, extra := ScopeSQL(f.Scopes, "h.site", "h.environment", "h.team_id", len(args)); condition != "" {
			conditions = append(conditions, condition)
			args = append(args, extra...)
		}
	}
	return conditions, args, nil
}

// versionParts renders the agent version of the aliased host row as an array
// of integers, so two versions compare part by part rather than as text - '0.
func versionParts(alias string) string {
	return "string_to_array(substring(" + alias + ".agent_version from '^v?(\\d+(?:\\.\\d+)*)'), '.')::int[]"
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

// Cursor is the key of the last host of the previous page: the order the page
// was read in, the value of the sorted column on that host and its identifier.
type Cursor struct {
	Sort  Sort
	Value string
	ID    string
	Set   bool
}

// ParseCursor reads a cursor issued by ListPaged. An empty value is the
// first page.
func ParseCursor(value string) (Cursor, error) {
	parts, err := paging.Decode(value, 3)
	if err != nil {
		return Cursor{}, err
	}
	if parts == nil {
		return Cursor{}, nil
	}
	order, err := ParseSort(parts[0])
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	if !sortColumns[order.column()].valid(parts[1]) {
		return Cursor{}, fmt.Errorf("%w: the key %q is not a %s", paging.ErrInvalidCursor, parts[1], order.column())
	}
	if _, err := uuid.Parse(parts[2]); err != nil {
		return Cursor{}, fmt.Errorf("%w: %v", paging.ErrInvalidCursor, err)
	}
	return Cursor{Sort: order, Value: parts[1], ID: parts[2], Set: true}, nil
}

// String renders the cursor for the next request.
func (c Cursor) String() string {
	return paging.Encode(c.Sort.String(), c.Value, c.ID)
}

// Matches says whether the cursor was issued for the given order.
func (c Cursor) Matches(order Sort) bool {
	return !c.Set || c.Sort.String() == order.String()
}

// ListPage is one page of the host list.
type ListPage struct {
	Items []Host `json:"items"`
	// Total is the number of hosts matching the filter across every page: the
	// operator is to know how many hosts a filter names, not how many fit on the
	// screen.
	Total int `json:"total"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListPaged reads the hosts matching the filter page by page, in the order the
// filter's Sort names - the hostname by default.
func (s *Store) ListPaged(ctx context.Context, filter ListFilter, cursor Cursor, limit int) (ListPage, error) {
	page := ListPage{Items: []Host{}}
	column, ok := sortColumns[filter.Sort.column()]
	if !ok {
		return page, fmt.Errorf("%w: %q", ErrInvalidSort, filter.Sort.Column)
	}
	if !cursor.Matches(filter.Sort) {
		return page, fmt.Errorf("%w: issued for the order %s, not %s", paging.ErrInvalidCursor, cursor.Sort, filter.Sort)
	}
	total, err := s.Count(ctx, filter)
	if err != nil {
		return page, err
	}
	page.Total = total

	conditions, args, err := filter.conditions()
	if err != nil {
		return page, err
	}
	direction, comparison := "asc", ">"
	if filter.Sort.Descending {
		direction, comparison = "desc", "<"
	}
	if cursor.Set {
		// The key comes back as text and is cast to the column's type in the query,
		// so one cursor format serves a name, a count and a timestamp alike.
		args = append(args, cursor.Value, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(%s, h.id) %s ($%d::%s, $%d::uuid)",
			column.expression, comparison, len(args)-1, column.kind, len(args)))
	}
	if limit <= 0 {
		limit = PageSize
	}
	// One row more than the page says whether there is a next page without
	// a second count.
	args = append(args, limit+1)
	clause := ""
	if len(conditions) > 0 {
		clause = "where " + strings.Join(conditions, " and ")
	}
	clause += fmt.Sprintf(" order by %s %s, h.id %s limit $%d", column.expression, direction, direction, len(args))

	items, err := s.query(ctx, clause, args...)
	if err != nil {
		return page, err
	}
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		page.NextCursor = Cursor{Sort: filter.Sort, Value: column.key(last), ID: last.ID, Set: true}.String()
	}
	if items != nil {
		page.Items = items
	}
	return page, nil
}

// Summary is what a sweep over the whole fleet needs to know about a host.
type Summary struct {
	ID             string
	Hostname       string
	OSDistribution string
	OSVersion      string
}

// PageSize is the size of one page of a sweep.
const PageSize = 500

// Sweep returns the next page of the fleet in the order of the key (hostname,
// id).
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
		select h.id, h.machine_id, h.hostname, h.site, h.environment, h.placement_changed_at,
		       coalesce(h.team_id::text, ''), coalesce(t.name, ''),
		       coalesce(h.owner, ''), h.tags,
		       coalesce(h.failure_domain, ''), h.release_channel, h.notes,
		       h.lifecycle_state, h.lifecycle_reason, h.lifecycle_changed_at, h.lifecycle_changed_by,
		       coalesce(h.os_family, ''), coalesce(h.os_distribution, ''),
		       coalesce(h.os_version, ''), coalesce(h.architecture, ''), coalesce(h.agent_version, ''),
		       h.connection_state, h.last_seen_at, coalesce(h.boot_id, ''),
		       coalesce(h.agent_build_commit, ''), h.agent_protocol_min, h.agent_protocol_max,
		       coalesce(h.config_fingerprint, ''), h.config_schema_version,
		       coalesce(h.helper_capability_mode, ''), h.helper_capability_supported,
		       h.reboot_required, h.failed_units, h.pending_updates, h.pending_security_updates,
		       coalesce(h.current_inventory_revision, ''), h.package_database_broken, h.enrolled_at,
		       coalesce(h.management_address, ''), coalesce(h.management_address_source, ''),
		       h.management_address_observed_at,
		       h.identity_enrolled, coalesce(h.identity_domain, ''), coalesce(h.identity_realm, ''),
		       h.identity_sssd_online, h.identity_checked_at,
		       h.maintenance_until, coalesce(h.maintenance_reason, ''),
		       coalesce(h.maintenance_by, ''), h.maintenance_at,
		       coalesce(h.last_connection_refusal_code, ''), h.last_connection_refusal_at,
		       coalesce(h.last_connection_refusal_detail, ''), coalesce(h.relay_identity, ''),
		       coalesce(c.rejestr, '[]'::json),
		       i.payload, i.observed_at
		from hosts h
		-- The team travels with every host the panel returns: the row that
		-- decides who may touch the host also names it on the screen.
		left join teams t on t.id = h.team_id
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
		if err := rows.Scan(&h.ID, &h.MachineID, &h.Hostname, &h.Site, &h.Environment,
			&h.PlacementChangedAt, &h.TeamID, &h.TeamName, &h.Owner, &h.Tags,
			&h.FailureDomain, &h.ReleaseChannel, &h.Notes,
			&h.LifecycleState, &h.LifecycleReason, &h.LifecycleChangedAt, &h.LifecycleChangedBy,
			&h.OSFamily, &h.OSDistribution, &h.OSVersion, &h.Architecture,
			&h.AgentVersion, &h.ConnectionState, &h.LastSeenAt, &h.BootID,
			&h.AgentBuildCommit, &h.AgentProtocolMin, &h.AgentProtocolMax,
			&h.ConfigFingerprint, &h.ConfigSchemaVersion,
			&h.HelperCapabilityMode, &h.HelperCapabilitySupported,
			&h.RebootRequired, &h.FailedUnits, &h.PendingUpdates, &h.PendingSecurityUpdates,
			&h.CurrentInventoryRevision, &h.PackageDatabaseBroken, &h.EnrolledAt,
			&h.ManagementAddress, &h.ManagementAddressSource, &h.ManagementAddressObservedAt,
			&h.Identity.Enrolled, &h.Identity.Domain, &h.Identity.Realm,
			&h.Identity.SSSDOnline, &h.Identity.CheckedAt,
			&windowUntil, &windowReason, &windowBy, &windowFrom,
			&refusalCode, &refusalAt, &refusalDetail, &h.RelayIdentity,
			&h.Capabilities, &identityPayload, &identityObservedAt); err != nil {
			return nil, err
		}
		if h.Identity.Enrolled {
			h.Identity.OfflineVerdict = judgeFromFragment(h.Identity.SSSDOnline,
				identityPayload, identityObservedAt)
		}
		// The verdict on the configuration is judged here, against the schema this
		// panel ships with: a host that reported a schema is on the legacy
		// configuration when it runs on no file (zero) or on a file older than the.
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
// version and the boot: the sources it was built from, the protocols it speaks
// and the configuration it runs on.
type AgentReport struct {
	BuildCommit         string
	ProtocolMin         int
	ProtocolMax         int
	ConfigFingerprint   string
	ConfigSchemaVersion int
	// HelperCapabilityMode and HelperCapabilitySupported are what the agent says
	// its root helper does with a signed capability. Empty and nil mean it has
	// not said.
	HelperCapabilityMode      string
	HelperCapabilitySupported *bool
}

// RecordAgentReport writes what the agent reported about itself at its Hello.
func (s *Store) RecordAgentReport(ctx context.Context, hostID string, report *AgentReport) error {
	const query = `
		update hosts
		   set agent_build_commit          = $2,
		       agent_protocol_min          = $3,
		       agent_protocol_max          = $4,
		       config_fingerprint          = $5,
		       config_schema_version       = $6,
		       helper_capability_mode      = $7,
		       helper_capability_supported = $8,
		       updated_at                  = now()
		 where id = $1`
	if report == nil {
		_, err := s.pool.Exec(ctx, query, hostID, nil, nil, nil, nil, nil, nil, nil)
		return err
	}
	var commit, fingerprint *string
	if report.BuildCommit != "" {
		commit = &report.BuildCommit
	}
	if report.ConfigFingerprint != "" {
		fingerprint = &report.ConfigFingerprint
	}
	var mode *string
	if report.HelperCapabilityMode != "" {
		mode = &report.HelperCapabilityMode
	}
	_, err := s.pool.Exec(ctx, query, hostID, commit, report.ProtocolMin, report.ProtocolMax,
		fingerprint, report.ConfigSchemaVersion, mode, report.HelperCapabilitySupported)
	return err
}

// The sources of the management address.
const (
	AddressFromSession = "session"
	AddressFromAgent   = "agent"
	AddressFromManual  = "manual"
)

// SetManagementAddress records the management address together with where it
// came from.
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

// Rename records the name the host reports for itself.
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
// rotation was introduced.
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
// unrevoked certificate.
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
func (s *Store) HostsWithoutCertificateSince(ctx context.Context, since time.Time) (int, error) {
	const query = `
		select count(*)
		from hosts h
		where h.lifecycle_state <> 'retired'
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

// NormalizeTags checks a tag list and returns it sorted and without repeats. A
// tag is 'key' or 'key=value' in the shape selector.
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

// TagCount is one tag of the catalogue with the hosts carrying it.
type TagCount struct {
	Tag string `json:"tag"`
	// Hosts counts the visible hosts carrying the tag, the retired ones too: a
	// tag on a retired host is still a tag somebody has to know about before
	// renaming it.
	Hosts int `json:"hosts"`
}

// TagCatalogue lists every tag any visible host carries, with the number of
// hosts carrying it, most used first.
func (s *Store) TagCatalogue(ctx context.Context, scopes []authz.Scope) ([]TagCount, error) {
	query := `
		select tag, count(*)
		  from hosts h, unnest(h.tags) as tag`
	var args []any
	if scopes != nil {
		if condition, extra := ScopeSQL(scopes, "h.site", "h.environment", "h.team_id", 0); condition != "" {
			query += " where " + condition
			args = append(args, extra...)
		}
	}
	query += " group by tag order by count(*) desc, tag"
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing the tags: %w", err)
	}
	defer rows.Close()
	catalogue := make([]TagCount, 0)
	for rows.Next() {
		var entry TagCount
		if err := rows.Scan(&entry.Tag, &entry.Hosts); err != nil {
			return nil, err
		}
		catalogue = append(catalogue, entry)
	}
	return catalogue, rows.Err()
}

// TagChange is one host whose tags a rename touched, with both lists for
// the trail.
type TagChange struct {
	HostID   string
	Hostname string
	Before   []string
	After    []string
}

// RenameTag replaces one tag by another on every visible host carrying it, in
// one transaction on the given handle: half a fleet renamed is a selector that
// matches half a fleet.
func (s *Store) RenameTag(ctx context.Context, tx pgx.Tx, from, to string, scopes []authz.Scope) ([]TagChange, error) {
	query := `select id, hostname, tags from hosts h where $1 = any(h.tags)`
	args := []any{from}
	if scopes != nil {
		if condition, extra := ScopeSQL(scopes, "h.site", "h.environment", "h.team_id", len(args)); condition != "" {
			query += " and " + condition
			args = append(args, extra...)
		}
	}
	// The rows are locked in a fixed order, so two renames running at
	// once take the hosts in the same order rather than each other.
	query += " order by id for update"
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("finding the hosts with the tag: %w", err)
	}
	var changes []TagChange
	for rows.Next() {
		var change TagChange
		if err := rows.Scan(&change.HostID, &change.Hostname, &change.Before); err != nil {
			rows.Close()
			return nil, err
		}
		changes = append(changes, change)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range changes {
		after := make([]string, 0, len(changes[i].Before))
		for _, tag := range changes[i].Before {
			if tag == from {
				tag = to
			}
			after = append(after, tag)
		}
		// The normalisation is the same one a single host's tags go through: it
		// drops the duplicate a host carrying both tags would end up with, and
		// sorts.
		normalized, err := NormalizeTags(after)
		if err != nil {
			return nil, err
		}
		changes[i].After = normalized
		if _, err := tx.Exec(ctx, `update hosts set tags = $2, updated_at = now() where id = $1`,
			changes[i].HostID, normalized); err != nil {
			return nil, fmt.Errorf("renaming the tag on host %s: %w", changes[i].HostID, err)
		}
	}
	return changes, nil
}

// The release channels a host may follow. The list is the same one the
// host table constrains.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// ErrInvalidChannel means a channel the panel does not have.
var ErrInvalidChannel = errors.New("invalid release channel")

// NormalizeChannel checks a channel name.
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

// SetTags replaces the tags of a host.
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

// MaxNotesLength bounds the notes of a host.
const MaxNotesLength = 4000

// ErrInvalidNotes means notes the panel does not accept; the message says
// what is wrong with them.
var ErrInvalidNotes = errors.New("invalid notes")

// NormalizeNotes checks the notes of a host. Empty notes are allowed and mean
// nobody wrote any.
func NormalizeNotes(notes string) (string, error) {
	notes = strings.TrimSpace(strings.ReplaceAll(notes, "\r\n", "\n"))
	if len([]rune(notes)) > MaxNotesLength {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidNotes, MaxNotesLength)
	}
	for _, r := range notes {
		if (r < ' ' && r != '\n' && r != '\t') || r == 0x7f {
			return "", fmt.Errorf("%w: control characters are not allowed", ErrInvalidNotes)
		}
	}
	return notes, nil
}

// SetNotes records the notes of a host. Empty notes clear the field.
func (s *Store) SetNotes(ctx context.Context, hostID, notes string) (*Host, error) {
	normalized, err := NormalizeNotes(notes)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx,
		`update hosts set notes = $2, updated_at = now() where id = $1`, hostID, normalized)
	if err != nil {
		return nil, fmt.Errorf("setting the notes: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

// MaxOwnerLength bounds the owner of a host.
const MaxOwnerLength = 128

// ErrInvalidOwner means an owner the panel does not accept; the message
// says what is wrong with it.
var ErrInvalidOwner = errors.New("invalid owner")

// NormalizeOwner checks an owner. An empty owner is allowed and means nobody:
// clearing the field is how a host is handed back to the pool.
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

// NormalizeFailureDomain checks a failure domain.
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

// MaxPlacementLength bounds the site and the environment of a host.
const MaxPlacementLength = 128

// ErrInvalidPlacement means a site or an environment the panel does not
// accept; the message says which and what is wrong with it.
var ErrInvalidPlacement = errors.New("invalid placement")

// NormalizePlacement checks a site and an environment.
func NormalizePlacement(site, environment string) (string, string, error) {
	site = strings.TrimSpace(site)
	environment = strings.TrimSpace(environment)
	for _, field := range []struct{ name, value string }{{"site", site}, {"environment", environment}} {
		if field.value == "" {
			return "", "", fmt.Errorf("%w: the %s is required", ErrInvalidPlacement, field.name)
		}
		if len(field.value) > MaxPlacementLength {
			return "", "", fmt.Errorf("%w: the %s is longer than %d characters",
				ErrInvalidPlacement, field.name, MaxPlacementLength)
		}
		for _, r := range field.value {
			if r < ' ' || r == 0x7f {
				return "", "", fmt.Errorf("%w: control characters are not allowed in the %s",
					ErrInvalidPlacement, field.name)
			}
		}
	}
	return site, environment, nil
}

// SetPlacement moves a host to a site and an environment.
func (s *Store) SetPlacement(ctx context.Context, hostID, site, environment string) (*Host, error) {
	site, environment, err := NormalizePlacement(site, environment)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx, `
		update hosts
		   set placement_changed_at = case when site = $2 and environment = $3
		                                   then placement_changed_at else now() end,
		       site = $2, environment = $3, updated_at = now()
		 where id = $1`, hostID, site, environment)
	if err != nil {
		return nil, fmt.Errorf("setting the placement: %w", err)
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
// reaching the host.
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
// host: its owner and its tags.
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

// SystemHistoryLimit is how many (kernel, distribution) pairs the panel keeps
// per host.
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

// RecordSystemHistory notes that the host was seen on this kernel and release
// at the given moment.
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
