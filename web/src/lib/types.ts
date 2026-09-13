// The types mirror the REST contract of the control plane.

/**
 * An adapter detected on the host. The name says what the host has
 * ("packages.apt"), not what the operation wants ("packages"). The reason
 * comes from the host: the interface is to repeat it, not guess the cause in
 * its own code.
 */
export type Capability = {
  name: string;
  version: number;
  available: boolean;
  read_only: boolean;
  reason?: string;
  features?: Record<string, boolean>;
};

export type Capabilities = Capability[];

/**
 * The state of one inventory module. The revision and the observation
 * timestamp belong to the module, so a tab shows the freshness of what it
 * displays.
 */
export type InventoryFragment<T> = {
  host_id: string;
  module: string;
  revision: string;
  source: string;
  payload: T;
  unavailable_reason?: string;
  observed_at: string;
};

export type HostIdentity = {
  enrolled: boolean;
  domain?: string;
  realm?: string;
  sssd_online: boolean | null;
  checked_at?: string;
};

export type Host = {
  id: string;
  hostname: string;
  machine_id: string;
  site: string;
  environment: string;
  owner?: string;
  lifecycle_state: string;
  os_family?: string;
  os_distribution?: string;
  os_version?: string;
  architecture?: string;
  agent_version?: string;
  connection_state: "online" | "offline" | "stale" | "unknown";
  last_seen_at?: string;
  boot_id?: string;
  // The maintenance window: an empty field means a host outside a window,
  // not a window of zero length. Campaigns skip a host in a window, and its
  // alerts wake nobody.
  maintenance?: { until: string; reason?: string; set_by?: string; set_at?: string };
  // Empty values mean an undetermined state, not zero.
  reboot_required: boolean | null;
  failed_units: number | null;
  pending_updates: number | null;
  pending_security_updates: number | null;
  current_inventory_revision?: string;
  package_database_broken: boolean;
  // The management address and its origin. A missing value means an
  // undetermined address and must be shown as undetermined.
  management_address?: string;
  management_address_source?: "session" | "agent" | "manual";
  management_address_observed_at?: string;
  enrolled_at: string;
  capabilities: Capabilities;
  identity: HostIdentity;
};

export type FleetSummary = {
  hosts: number;
  online: number;
  offline: number;
  active_sessions: number;
  reboot_required: number;
  with_failed_units: number;
  hosts_with_security_updates: number;
  quarantined_hosts: number;
};

export type Job = {
  id: string;
  host_id: string;
  action_type: string;
  state: string;
  payload: unknown;
  payload_hash: string;
  requires_approval: boolean;
  // A destructive operation requires two people's consent, so the flag
  // alone is not enough: what counts is how many approvals there are and
  // how many are needed.
  required_approvals: number;
  collected_approvals: number;
  created_by: string;
  approved_by?: string;
  result_status?: string;
  result_error_code?: string;
  result_message?: string;
  expires_at: string;
  created_at: string;
  finished_at?: string;
};

export type UnitState = {
  name: string;
  active_state: string;
  sub_state: string;
  main_pid: number;
  n_restarts: number;
};

export type Attempt = {
  id: string;
  attempt_number: number;
  status?: string;
  exit_code?: number;
  error_code?: string;
  message?: string;
  stdout?: string;
  stderr?: string;
  replayed: boolean;
  unit_state_before?: UnitState;
  unit_state_after?: UnitState;
  detail?: Record<string, unknown>;
  finished_at?: string;
};

export type Campaign = {
  id: string;
  name: string;
  action_type: string;
  state: string;
  canary_size: number;
  wave_size: number;
  max_concurrent: number;
  failure_threshold_percent: number;
  failure_threshold_absolute: number;
  reboot_policy: string;
  requires_approval: boolean;
  // The fingerprint of what the approver sees: the operation, the payload,
  // the host list and the rollout policy. The consent must give it.
  approval_fingerprint: string;
  created_by: string;
  approved_by?: string;
  paused_by?: string;
  pause_reason?: string;
  created_at: string;
};

/**
 * One entry of the durable campaign timeline.
 *
 * The content depends on the event kind, so it is a bag of fields rather
 * than a rigid shape: a target event carries the host and the wave, a
 * campaign event - the pause reason. Pretending one shape would force
 * filling in fields the given event does not have.
 */
export type TimelineEntry = {
  id: number;
  aggregate_type: string;
  event_type: string;
  occurred_at: string;
  payload?: {
    host_id?: string;
    wave?: number;
    error_code?: string;
    message?: string;
    pause_reason?: string;
    job_id?: string;
  };
};

export type CampaignTarget = {
  host_id: string;
  hostname?: string;
  wave: number;
  state: string;
  error_code?: string;
  message?: string;
  // A campaign creates several operations for a host one after another, so
  // the progress has to be bound to the operation, not to the host alone.
  job_id?: string;
  reboot_job_id?: string;
  health_job_id?: string;
  // The planning operation: its result is the plan the operator consents to.
  plan_job_id?: string;
};

export type CampaignReport = {
  state: string;
  totals: Record<string, number>;
  waves: { wave: number; is_canary: boolean; totals: Record<string, number>; completed: boolean }[];
  failures: CampaignTarget[];
};

export type AuditEvent = {
  id: number;
  occurred_at: string;
  actor_type: string;
  actor_id: string;
  action: string;
  target_type?: string;
  target_id?: string;
  outcome: "success" | "failure" | "denied";
  detail: Record<string, unknown>;
};

export type Whoami = {
  subject: string;
  display_name?: string;
  kind: string;
  roles: string[];
  bindings: { role: string; scope: { site: string; environment: string } }[];
  /** The permissions in any scope; the interface hides unbacked sections with them. */
  permissions: string[];
};

export type DirectoryUser = {
  uid: string;
  first_name?: string;
  last_name?: string;
  email?: string[];
  uid_number?: string;
  groups?: string[];
  disabled: boolean;
  ssh_key_fingerprints?: string[];
};

export type DirectoryGroup = {
  name: string;
  description?: string;
  gid_number?: string;
  members?: string[];
};

export type SudoRule = {
  name: string;
  enabled: boolean;
  users?: string[];
  user_groups?: string[];
  critical: boolean;
  critical_reasons?: string[];
};

export type HBACRule = {
  name: string;
  enabled: boolean;
  allows_everything: boolean;
  user_groups?: string[];
  hosts?: string[];
  host_groups?: string[];
};

export type InventoryRevision = {
  revision: string;
  observed_at: string;
  payload: Record<string, any>;
};

/**
 * An account seen on the host. A null value means an undetermined state and
 * must be shown as unknown, not as "no" - otherwise the panel would claim
 * the account has open access although it did not check.
 */
export type LocalAccount = {
  name: string;
  uid: number;
  gid: number;
  home?: string;
  shell?: string;
  gecos?: string;
  source: "local" | "directory" | "system" | "unknown";
  groups: string[];
  locked: boolean | null;
  password_set: boolean | null;
  ssh_keys: { fingerprint: string; type?: string; comment?: string; source?: string }[];
  unavailable_reason?: string;
  observed_at: string;
};

export type Principal = {
  id: string;
  subject: string;
  display_name?: string;
  kind: string;
  /** May be absent: an identity without its own bindings has roles from the group mappings. */
  bindings?: { role: string; scope: { site: string; environment: string } }[];
};

export type GroupMapping = {
  id: string;
  issuer: string;
  group_name: string;
  role: string;
  site: string;
  environment: string;
  created_by: string;
  created_at: string;
};

/**
 * A fleet CA. The "pending" state means the CA is already recognised and
 * distributed, but does not sign yet - handing it the signing requires the
 * whole fleet to have learnt it.
 */
export type Authority = {
  subject: string;
  serial: string;
  fingerprint: string;
  not_before: string;
  not_after: string;
  state: "active" | "pending" | "retired";
  hosts_using: number;
  prepared_at?: string;
  hosts_missing?: number;
  ready_to_activate?: boolean;
};
