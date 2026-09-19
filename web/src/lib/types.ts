// The types mirror the REST contract of the control plane.

/**
 * An adapter detected on the host. The name says what the host has
 * ("packages.
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
 * The state of one inventory module.
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
  offline_verdict?: OfflineVerdict;
};

/**
 * The panel's judgement on directory logins during an outage.
 */
export type OfflineVerdict = {
  verdict: "cached_logins_until" | "cached_logins_indefinitely" | "no_cached_logins" | "unknown";
  until?: string;
  in_force: boolean;
  reason: string;
};

export type Host = {
  id: string;
  hostname: string;
  machine_id: string;
  site: string;
  environment: string;
  owner?: string;
  /** What the host goes down with - a rack, a zone, a cluster - as an operator recorded it; absent when nobody placed it. */
  failure_domain?: string;
  // What operators recorded about the host: "key" or "key=value". Always a
  // list; a host without tags has an empty one.
  tags: string[];
  // Which agent releases the host follows. A policy of the panel, always
  // set: a host on no channel would follow nothing.
  release_channel: ReleaseChannel;
  lifecycle_state: string;
  // The decision behind a state other than active: the reason given and
  // when it was taken. Absent for a host that has always been active.
  lifecycle_reason?: string;
  lifecycle_changed_at?: string;
  lifecycle_changed_by?: string;
  placement_changed_at?: string;
  os_family?: string;
  os_distribution?: string;
  os_version?: string;
  architecture?: string;
  agent_version?: string;
  connection_state: "online" | "offline" | "stale" | "unknown";
  last_seen_at?: string;
  boot_id?: string;
  // What the agent reported about itself at its last Hello beyond the
  // version: the commit it was built from, the protocols it speaks, and the
  // configuration it runs on.
  agent_build_commit?: string;
  agent_protocol_min?: number;
  agent_protocol_max?: number;
  // The digest of the effective agent.
  config_fingerprint?: string;
  config_schema_version?: number;
  config_legacy?: boolean;
  // The maintenance window: an empty field means a host outside a window,
  // not a window of zero length.
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
  // Why the gateway last turned the host away since its last session.
  last_connection_refusal?: ConnectionRefusal;
  enrolled_at: string;
  capabilities: Capabilities;
  identity: HostIdentity;
};

/**
 * A refusal of the gateway.
 */
export type ConnectionRefusal = {
  code: string;
  at: string;
  detail?: string;
};

/** The refusal codes that an identity recovery answers. */
export const RECOVERABLE_REFUSALS = ["certificate_expired", "unknown_certificate", "revoked_certificate"];

/** The refusal in the operator's words; an unlisted code shows as it came. */
export function refusalName(code: string): string {
  switch (code) {
    case "certificate_expired": return "certificate expired";
    case "certificate_not_yet_valid": return "certificate not yet valid";
    case "unknown_certificate": return "certificate unknown";
    case "revoked_certificate": return "certificate revoked";
    case "identity_mismatch": return "identity mismatch";
    case "relay_identity_missing": return "relay did not attest the certificate";
    case "relay_identity_invalid": return "relay attestation unreadable";
    case "relay_scope_mismatch": return "relay of another site or environment";
    case "relay_envelope_invalid": return "relay envelope invalid";
    case "relay_body_hash_mismatch": return "relayed payload altered";
    case "relay_sequence_replayed": return "relayed message replayed";
    case "relay_host_signature_invalid": return "host signature invalid";
    case "blocked_upgrade_required": return "agent upgrade required";
    default:
      return code.startsWith("lifecycle_") ? `host ${code.slice("lifecycle_".length)}` : code;
  }
}

/**
 * One node of a campaign selector: exactly one field is set. A combinator
 * holds other nodes; a leaf names one fact about the host.
 */
export type SelectorExpression = {
  all?: SelectorExpression[];
  any?: SelectorExpression[];
  not?: SelectorExpression;
  site?: string;
  environment?: string;
  os_family?: string;
  tag?: string;
  /** A saved group, by identifier or by name. */
  group?: string;
  capability?: string;
  connection_state?: string;
  lifecycle_state?: string;
  owner?: string;
  /** The release channel the host follows: an upgrade in waves names beta first. */
  channel?: ReleaseChannel;
  /** A prefix of the OS version: '12' names every 12.x. */
  os_version?: string;
  /** 'true' or 'false'; a host that has not reported the fact is in neither. */
  security_updates?: string;
  reboot_required?: string;
  failed_units?: string;
  /** A comparison: '< 0.49.0', '>= 0.49.0', or a bare version for equality. */
  agent_version?: string;
  /** A relay by identifier or name, through whose open session the host connects. */
  relay?: string;
  failure_domain?: string;
};

/** The release channels a host may follow. */
export type ReleaseChannel = "stable" | "beta";
export const RELEASE_CHANNELS: ReleaseChannel[] = ["stable", "beta"];

/** A saved host selection: a fixed member list or a selector resolved when read. */
export type HostGroup = {
  id: string;
  name: string;
  description?: string;
  kind: "static" | "dynamic";
  selector?: SelectorExpression;
  created_by: string;
  created_at: string;
  updated_at: string;
  // The size: counted in the database for a static group, resolved for the
  // caller for a dynamic one. Missing means the count is not known, not zero.
  member_count?: number;
  // Why a dynamic group does not resolve any more, e.g. a group it names was deleted.
  unresolvable?: string;
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
  package_database_broken: number;
  sssd_offline: number;
  in_maintenance: number;
  // The attention counters the database computes over the visible fleet.
  failed_jobs_24h?: number;
  pending_enrollment_requests?: number;
  agents_behind_latest?: number;
  latest_agent_version?: string;
  agent_certificates_expiring?: number;
  agent_certificates_expired?: number;
  degraded_relays?: number;
  // The lifecycle document's panel-level alarms, as counters: a relay buffer
  // at least 70 % full, the audit trail's duplicate identities and
  // enrollment refusals, and agents on a protocol the panel does not speak.
  relays_buffer_high?: number;
  duplicate_identities_24h?: number;
  enrollment_refusals_1h?: number;
  agents_unsupported?: number;
};

/**
 * What a decommission ended with.
 */
export type DecommissionOutcome = {
  host_id: string;
  lifecycle_state: string;
  reason: string;
  phase: "committed" | "no_session" | "timeout";
  remote_cleanup_unconfirmed: boolean;
  running_tasks: string[];
  leases_dropped: boolean;
  jobs_canceled: number;
  certificates_revoked: number;
  session_closed: boolean;
};

export type Job = {
  id: string;
  host_id: string;
  hostname?: string;
  campaign_id?: string;
  action_type: string;
  /** The cancel protocol: when it was asked, when the host answered, and what it found. */
  cancel_requested_at?: string;
  cancel_ack_at?: string;
  cancel_outcome?: string;
  cancel_phase?: string;
  state: string;
  payload: unknown;
  payload_hash: string;
  requires_approval: boolean;
  // A destructive operation requires two people's consent, so the flag alone
  // is not enough: what counts is how many approvals there are and how many
  // are needed.
  required_approvals: number;
  collected_approvals: number;
  created_by: string;
  approved_by?: string;
  result_status?: string;
  result_error_code?: string;
  result_message?: string;
  // A queued job that got no capacity says which budget it waits for, as
  // awaiting_budget:<key>. Absent when nothing holds the job.
  wait_reason?: string;
  // The urgency the order stated for the budgets; absent when it was left
  // to the scheduler.
  budget_class?: string;
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
  /**
   * The host's reading of itself after the change: which verifier of the
   * contract looked, whether it saw the state that was ordered, what it
   * expected, what it found and why the two differ.
   */
  verification?: {
    verifier?: string;
    verified?: boolean;
    expected?: string;
    observed?: string;
    reason?: string;
  };
  // The delivery to the host, the agent's acknowledgement, the start it
  // reported and the end: the window of the attempt on the host.
  dispatched_at?: string;
  accepted_at?: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
};

/** The evidence of a consent: written once when a campaign is approved. */
export type CampaignApproval = {
  id: string;
  campaign_id: string;
  approval_fingerprint: string;
  requested_by: string;
  approved_by: string;
  authentication: "session" | "api_token";
  acr?: string;
  amr?: string[];
  authenticated_at?: string;
  reason?: string;
  change_ticket?: string;
  created_at: string;
};

export type Campaign = {
  id: string;
  name: string;
  action_type: string;
  // The payload as ordered, in the shape of a single-host operation. A
  // rollback plan starts from it: the same path, the same interface.
  payload?: unknown;
  // planning, planned, awaiting_approval, canary, manual_gate, running,
  // paused, canceling, and the settled ones: completed,
  // completed_with_issues, failed, plan_failed, expired, canceled.
  state: string;
  canary_size: number;
  wave_size: number;
  max_concurrent: number;
  failure_threshold_percent: number;
  failure_threshold_absolute: number;
  reboot_policy: string;
  requires_approval: boolean;
  // What the campaign does with a host that is not connected when its turn
  // comes, and how long it waits for such a host under a waiting policy.
  offline_policy: string;
  deadline_at?: string;
  // The stop after the canary: whether the campaign asks for a decision
  // before the waves, and who gave it.
  manual_gate: boolean;
  gate_advanced_by?: string;
  gate_advanced_at?: string;
  // How many hosts may lose their session mid-task before the campaign
  // pauses; zero means no such check.
  connectivity_lost_absolute: number;
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
  campaign_id: string;
  host_id: string;
  hostname?: string;
  wave: number;
  cancel_requested_at?: string;
  cancel_outcome?: string;
  cancel_phase?: string;
  // One of TARGET_STATES in lib/targets.
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
  // Hosts per target state: succeeded, no_change, failed, unknown, skipped,
  // canceled and the rest, each its own number.
  totals: Record<string, number>;
  waves: { wave: number; is_canary: boolean; totals: Record<string, number>; completed: boolean }[];
  // The hosts to look at: the ones that failed and the ones that ended
  // unknown, each with its state on the row.
  failures: CampaignTarget[];
  // Hosts that came back from being offline with a different plan: they ran
  // nothing, because the consent covered the old plan.
  plan_changed?: CampaignTarget[];
  // Hosts still waiting for their connection.
  offline_queued?: string[];
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
  /** The session behind the event and how it was authenticated; absent for a token, an agent or the system. */
  session_id?: string;
  acr?: string;
  amr?: string[];
  auth_time?: string;
  /** The target host as it was when the event was written. */
  target_hostname?: string;
  target_address?: string;
  approval_chain?: { created_by: string; approvers: string[] };
  before?: unknown;
  after?: unknown;
  /** The actor as it was when the event was written; a link is made only from resource_type host, relay or campaign. */
  actor?: {
    principal_id?: string; subject?: string; display_name?: string; kind?: string;
    resource_type?: string; resource_id?: string; resource_name?: string; credential_id?: string;
  };
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
  gid_number?: string;
  home_directory?: string;
  shell?: string;
  groups?: string[];
  disabled: boolean;
  ssh_key_fingerprints?: string[];
  /** RFC3339; missing means the directory holds no expiration, not "never checked". */
  password_expires_at?: string;
  principal_expires_at?: string;
  last_password_change?: string;
  /** A soft-deleted account: the entry stays with its UID and its trail. */
  preserved?: boolean;
};

/** A host entry of the directory; enrolled means it holds a host key. */
export type DirectoryHost = {
  fqdn: string;
  description?: string;
  enrolled: boolean;
  /** The directory's generalized time, shown as it came. */
  enrolled_at?: string;
  member_of?: string[];
  managed_by?: string[];
};

export type DirectoryHostGroup = {
  name: string;
  description?: string;
  hosts?: string[];
  host_groups?: string[];
};

/** A Kerberos service principal; has_keytab null means the directory did not say. */
export type DirectoryService = {
  principal: string;
  service: string;
  host: string;
  has_keytab: boolean | null;
  managed_by?: string[];
  aliases?: string[];
};

/** The health of the directory connector, as the panel itself sees it. */
export type IdentityConnector = {
  principal: string;
  keytab_readable: boolean;
  keytab_detail?: string;
  /** A keytab file carries no expiry date; only the key version and its stamp. */
  keytab_entries: { principal: string; kvno: number; timestamp?: string }[];
  last_success_at?: string | null;
  last_error?: string;
  last_error_at?: string | null;
  cache_entries: number;
  cache_oldest_at?: string | null;
  cache_ttl_seconds: number;
};

export type IdentityOfflineHost = {
  id: string;
  hostname: string;
  site?: string;
  environment?: string;
  checked_at?: string | null;
  offline_verdict: OfflineVerdict;
};

export type IdentityStatus = {
  configured: boolean;
  reachable?: boolean;
  principal?: string;
  summary?: string;
  error?: string;
  detail?: string;
  connector?: IdentityConnector;
  hosts?: {
    offline_from_directory: IdentityOfflineHost[];
    offline_count: number;
    by_verdict: Record<string, number>;
  };
};

export type DirectoryGroup = {
  name: string;
  description?: string;
  gid_number?: string;
  members?: string[];
};

export type SudoRule = {
  name: string;
  description?: string;
  enabled: boolean;
  users?: string[];
  user_groups?: string[];
  hosts?: string[];
  host_groups?: string[];
  commands?: string[];
  command_groups?: string[];
  run_as?: string[];
  run_as_groups?: string[];
  options?: string[];
  all_users: boolean;
  all_hosts: boolean;
  all_commands: boolean;
  run_as_any_user: boolean;
  critical: boolean;
  critical_reasons?: string[];
};

export type HBACRule = {
  name: string;
  description?: string;
  enabled: boolean;
  allows_everything: boolean;
  users?: string[];
  user_groups?: string[];
  hosts?: string[];
  host_groups?: string[];
  services?: string[];
  service_groups?: string[];
  all_users: boolean;
  all_hosts: boolean;
  all_services: boolean;
};

/** The plan of a directory change: the impact, read before anybody approves. */
export type DirectoryPlan = {
  summary: string;
  steps?: string[];
  affected_users?: string[];
  reachable_hosts?: string[];
  sudo_rules?: string[];
  warnings?: string[];
  conflicts?: string[];
  replaces?: boolean;
};

export type DirectoryChange = {
  id: string;
  action_type: string;
  state: string;
  plan?: DirectoryPlan;
  payload_hash?: string;
  requires_approval?: boolean;
  created_by?: string;
  approved_by?: string;
  result_message?: string;
  phases?: { name: string; status: string; message?: string }[];
  created_at?: string;
  finished_at?: string | null;
  /** True while the one-time password of a finished reset waits for its requester. */
  secret_available?: boolean;
};

/** The one-time password of a reset, handed out exactly once to the requester. */
export type RevealedSecret = {
  uid: string;
  one_time_password: string;
  expires_on_first_login: boolean;
};

/** The directory's own verdict on one user, host and service. */
export type AccessSimulation = {
  user: string;
  host: string;
  service: string;
  allowed: boolean;
  matched: string[];
  not_matched: string[];
  errors?: string[];
  warnings?: string[];
};

/**
 * The effective access of one host.
 */
export type HostAccess = {
  hostname: string;
  known: boolean;
  detail?: string;
  fqdn?: string;
  enrolled: boolean;
  host_groups: string[];
  hbac_rules: (HBACRule & { via: string[]; reached_users?: string[] })[];
  sudo_rules: (SudoRule & { via: string[]; reached_users?: string[] })[];
  /** Whether the directory half was read; the local half does not depend on it. */
  directory: { configured: boolean; reachable: boolean; error?: string };
  local_sudoers: LocalSudoersState;
  local_sudo_rules: LocalSudoRule[];
  /** One sentence per local grant that makes somebody root on this host. */
  root_equivalent_warnings: string[];
};

/**
 * The state of the local sudo policy. `read` false with a reason is a
 * policy the panel does not know - never a host without sudo.
 */
export type LocalSudoersState = {
  read: boolean;
  reason?: string;
  observed_at?: string;
  revision?: string;
  files?: { path: string; included_from?: string; lines: number; reason?: string }[];
  problems?: { source: string; line: number; text: string; reason: string }[];
  passwordless_globally: boolean;
};

/** One rule of /etc/sudoers or a drop-in, as the helper parsed it. */
export type LocalSudoRule = {
  users: string[];
  hosts: string[];
  run_as?: string[];
  run_as_groups?: string[];
  run_as_self?: boolean;
  commands: string[];
  tags?: string[];
  nopasswd: boolean;
  all_users: boolean;
  all_hosts: boolean;
  all_commands: boolean;
  run_as_any_user: boolean;
  root_equivalent: boolean;
  critical: boolean;
  critical_reasons?: string[];
  /** The file and line the rule was read from. */
  source: string;
  line: number;
  text: string;
  via: string[];
  reaches_host: boolean;
  reached_users?: string[];
};

/**
 * The platform picture of the system module, laid over the basic facts of
 * the fragment.
 */
export type SystemSnapshot = {
  hostname?: string;
  boot_id?: string;
  os?: { family?: string; distribution?: string; version?: string; kernel?: string; architecture?: string; pretty_name?: string; codename?: string };
  hardware?: { cpu_cores?: number; memory_bytes?: number; root_fs_bytes?: number; root_fs_free_bytes?: number; virtualization?: string };
  cpu?: { model?: string; vendor?: string; threads?: number; cores?: number; sockets?: number; flags?: string[]; flag_count?: number; mhz?: number };
  memory?: { total_bytes?: number; swap_total_bytes?: number };
  dmi?: {
    vendor?: string; product?: string; version?: string; family?: string; board_vendor?: string; board_name?: string;
    chassis_type?: string; serial?: string; uuid?: string; board_serial?: string; chassis_serial?: string;
  };
  firmware?: { vendor?: string; version?: string; date?: string; mode?: string };
  kernel?: { release?: string; version?: string; architecture?: string; cmdline?: string };
  distribution?: { id?: string; name?: string; version?: string; codename?: string; pretty_name?: string; like?: string[] };
  virtualization?: { kind?: string; source?: string };
  timezone?: string;
  boot?: { booted_at?: string; uptime_seconds?: number };
  missing?: Record<string, string>;
  /** When the platform picture was read; the fragment's own timestamp is the report's. */
  observed_at?: string;
};

/** One platform the panel has seen a host on. */
export type SystemHistoryEntry = {
  kernel: string;
  distribution: string;
  distribution_version: string;
  first_seen_at: string;
  last_seen_at: string;
};

export type InventoryRevision = {
  revision: string;
  observed_at: string;
  payload: Record<string, any>;
};

/**
 * An account seen on the host.
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
  /** The expiry date as YYYY-MM-DD; absent means no expiry or an unread record. */
  expires_at?: string;
  unavailable_reason?: string;
  observed_at: string;
};

export type Principal = {
  id: string;
  subject: string;
  display_name?: string;
  kind: string;
  /** May be absent: an identity without its own bindings has roles from the group mappings. */
  bindings?: RoleBinding[];
  /** The live API tokens; the value of a token is never among them. */
  tokens?: ApiToken[];
};

/** A role in a scope; a binding with a validity ends by itself. */
export type RoleBinding = {
  role: string;
  scope: { site: string; environment: string };
  /** Absent means until revoked. */
  valid_until?: string;
};

/** One identity of the access review, with what the reviewer should look at. */
export type ReviewedPrincipal = {
  id: string;
  subject: string;
  display_name?: string;
  kind: string;
  created_at: string;
  last_login_at?: string;
  last_token_use_at?: string;
  last_seen_at?: string;
  /** Absent means never used. */
  days_since_use?: number;
  earliest_expiry?: string;
  bindings: (RoleBinding & { expired: boolean; created_by: string; created_at: string })[];
  tokens: ApiToken[];
  flags: ReviewFlag[];
};

export type ReviewFlag = "unused_90_days" | "expires_soon" | "admin_without_expiry" | "token_older_than_year";

export type AccessReview = {
  items: ReviewedPrincipal[];
  count: number;
  flagged: number;
  reviewed_at: string;
  thresholds: { unused_days: number; expires_soon_days: number; token_max_days: number };
};

/** One row of the settings screen; a secret is masked and says only whether it is set. */
export type SettingsFact = {
  key: string;
  value: string | number | boolean | string[] | null;
  secret?: boolean;
  configured?: boolean;
};

export type SettingsArea = {
  key: string;
  title: string;
  facts: SettingsFact[];
};

export type Settings = {
  source: string;
  note: string;
  areas: SettingsArea[];
};

export type ApiToken = {
  id: string;
  description?: string;
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
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
 * A fleet CA.
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

/** One stage of an installation, as the panel really sees it. */
export type EnrollmentStepState = "waiting" | "done" | "failed";

export type EnrollmentStep = {
  key: "token" | "certificate" | "connected" | "inventory";
  state: EnrollmentStepState;
  // The reason the step does not go on, when the panel knows it: a refused
  // attempt recorded against the order, or a readiness gate the host has not
  // passed in time.
  error_code?: string;
  detail?: string;
};

/**
 * An enrollment order. The token is not here: it exists only in the answer
 * to placing the order, and the screen keeps it in memory alone.
 */
export type EnrollmentOrder = {
  id: string;
  description?: string;
  site: string;
  environment: string;
  kind: "agent" | "relay";
  purpose: "new" | "replace_identity" | "relay";
  relay_id?: string;
  // What the operator knew about the machine when ordering: recorded on
  // the host the moment it enrolls.
  owner?: string;
  tags?: string[];
  max_uses: number;
  uses: number;
  status: "pending" | "enrolled" | "expired" | "revoked" | "failed";
  enrolled_host_id?: string;
  expires_at: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  // The ready configuration of the order, without the token.
  config_url: string;
  steps?: EnrollmentStep[];
};

/** The state of a relay: the same four states the metrics count. */
export type RelayState = "active" | "silent" | "never_seen" | "revoked";

/** What a relay reported about itself at its last heartbeat. */
export type RelayBuffer = {
  buffer_bytes: number;
  buffer_max_bytes: number;
  buffered_items: number;
  buffer_dropped: number;
  sessions: number;
  relay_version?: string;
  reported_at: string;
};

/**
 * A relay of a site: the route of an installation in an isolated site, and
 * the point a whole site hangs on once it is there.
 */
export type Relay = {
  id: string;
  name: string;
  site: string;
  environment?: string;
  serial?: string;
  not_after?: string;
  enrolled_at: string;
  last_seen_at?: string;
  revoked_at?: string;
  revocation_reason?: string;
  state: RelayState;
  hosts_attested: number;
  buffer?: RelayBuffer;
  certificate_not_after?: string;
  advertised_names?: string[];
};

/** A host whose open session came through a relay. */
export type RelayHost = {
  host_id: string;
  hostname: string;
  site: string;
  environment?: string;
  lifecycle_state: string;
  agent_version?: string;
  connected_at: string;
  last_heartbeat_at?: string;
};

export type RelayDetail = { relay: Relay; hosts: RelayHost[] };

/**
 * One capacity budget as the fleet page lists it: the key, the capacity
 * somebody set, the tokens held right now, and who holds or asks for them.
 */
export type Budget = {
  key: string;
  capacity: number;
  /** The weight of the tokens held under live leases. */
  used: number;
  /** The claimants holding tokens or waiting for them; the fair share divides the capacity between them. */
  claimants: number;
  /** The single-host jobs standing in the queue for this budget. */
  waiting_jobs: number;
};

/** A configured budget as its own record, read for its entity tag before a write. */
export type BudgetLimit = {
  key: string;
  capacity: number;
  note: string;
  updated_at: string;
};

export type InstallationCommand = {
  key: "repository" | "package" | "config" | "ca" | "enroll" | "start";
  command: string;
};

export type InstallationFamily = {
  key: string;
  label: string;
  package_manager: string;
  steps: InstallationCommand[];
};

/**
 * Everything a host needs before it holds a token.
 */
export type InstallationProfile = {
  kind: "agent" | "relay";
  site: string;
  environment: string;
  architecture: string;
  channel: string;
  reason_required: boolean;
  connection: {
    enrollment_url: string;
    gateway_urls: string[];
    relay?: { id: string; name: string; site: string };
  };
  config: { path: string; content: string };
  ca: { path: string; pem: string; fingerprint_sha256: string; subject: string; not_after: string };
  repository: { configured: boolean; url: string; key_url: string; package: string };
  architectures: string[];
  families: InstallationFamily[];
  warnings?: string[];
};

/** One category of the fleet and how many hosts fall into it. */
export type Facet = { key: string; count: number };

/** The activity behind the dashboard widgets, computed in the database. */
export type FleetActivity = {
  hours: string[];
  succeeded: number[];
  failed: number[];
  other: number[];
  by_os_family: Facet[];
  by_site: Facet[];
  by_environment: Facet[];
  by_agent_version: Facet[];
  by_connection_state: Facet[];
  by_lifecycle_state: Facet[];
};

/* ---------------------------------------------------------------------- */
/* Monitoring: the metrics the agent samples and the panel's own rules.    */
/* ---------------------------------------------------------------------- */

/** The window of a metrics query; the two long ones come back as rollups. */
export type MetricRange = "3h" | "24h" | "7d" | "30d";

export type FilesystemSample = {
  mount: string;
  used_bytes: number;
  total_bytes: number;
  inodes_used: number;
  inodes_total: number;
};

/** The rates are absent on the first point of a window: a rate needs two samples. */
export type InterfaceSample = {
  name: string;
  rx_bytes_per_second?: number;
  tx_bytes_per_second?: number;
};

/**
 * One sample of a host, or one rollup step of them.
 */
export type MetricPoint = {
  at: string;
  cpu_percent: number;
  load1: number;
  load5: number;
  load15: number;
  memory_used: number;
  memory_total: number;
  memory_available: number;
  swap_used: number;
  swap_total: number;
  uptime_seconds: number;
  filesystems?: FilesystemSample[];
  interfaces?: InterfaceSample[];
  /** The agent's own footprint; absent where the agent did not report it, never zero. */
  agent_rss_bytes?: number;
  agent_cpu_percent?: number;
  agent_goroutines?: number;
  agent_open_fds?: number;
  /** Present only while the root helper runs; it sleeps between orders. */
  helper_rss_bytes?: number;
  cpu_percent_max?: number;
  memory_used_max?: number;
  agent_rss_bytes_max?: number;
  agent_cpu_percent_max?: number;
};

/** A stretch of a chart window with no reading; the reason is the typed code
 *  of the refusal that explains it. */
export type MetricGap = {
  from: string;
  to: string;
  /** How many points of the range the hole swallowed. */
  steps: number;
  reason?: string;
  refused_samples?: number;
};

/** What the panel would not store from a host, per typed reason code and per day. */
export type MetricRefusal = {
  reason: string;
  samples: number;
  first_sample_at: string;
  last_sample_at: string;
  last_refused_at: string;
};

/** Where the panel had to stamp a host's readings with its own time. */
export type MetricClockSubstitution = {
  reason: string;
  /** Positive means the host's clock runs ahead of the panel's. */
  skew_millis: number;
  samples: number;
  last_at: string;
};

export type HostMetrics = {
  host_id: string;
  range: MetricRange;
  /** 60 for raw samples, 900 for the rollups of the long windows. */
  step_seconds: number;
  points: MetricPoint[];
  /** The stretches of the window with no reading; a hole is not a row of zeroes. */
  gaps: MetricGap[];
  /** The newest sample of the host at all, or null before the first one. */
  latest: MetricPoint | null;
  last_sample_at?: string | null;
  sampling_interval_seconds: number;
  source: "agent";
};

export type AlertSeverity = "critical" | "warning" | "info";
export type AlertState = "pending" | "firing" | "resolved";

export type Alert = {
  id: string;
  rule_id: string;
  rule_name: string;
  metric: string;
  severity: AlertSeverity;
  state: AlertState;
  value: number;
  detail?: string;
  started_at: string;
  fired_at?: string | null;
  resolved_at?: string | null;
  silenced: boolean;
  host_id: string;
  hostname: string;
};

/** A silence always ends: it is a sensor turned off, with an owner and a reason. */
export type Silence = {
  id: string;
  /** Empty when the silence covers every host: a fleet-wide or a global one. */
  host_id?: string;
  hostname?: string;
  /** Empty when the silence covers every rule of the host. */
  rule_id?: string | null;
  rule_name?: string | null;
  until: string;
  reason: string;
  /** Keeps back the security alerts of the installation; names no host and no rule. */
  global?: boolean;
  /** One message per channel when it ends, naming what it kept back. */
  send_summary?: boolean;
  created_by: string;
  created_at: string;
  expired_at?: string | null;
};

export type RuleOperator = "gt" | "lt" | "gte" | "lte";

/** Which hosts a rule applies to; an empty selector is the whole fleet. */
export type RuleSelector = {
  site?: string;
  environment?: string;
  os_family?: string;
  host_ids?: string[];
  /** Every listed tag has to be on the host. */
  tags?: string[];
  /** The host has to be in one of the groups, by identifier or name. */
  groups?: string[];
  owner?: string;
  /** The text form of a campaign selector, e.g. "agent_version < 0.49.0 or reboot_required = true". */
  expression?: string;
};

export type AlertRule = {
  id: string;
  name: string;
  metric: string;
  operator: RuleOperator;
  threshold: number;
  /** How long the condition must hold before the alert fires. */
  for_minutes: number;
  severity: AlertSeverity;
  selector: RuleSelector;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type AlertRuleInput = {
  name: string;
  metric: string;
  operator: RuleOperator;
  threshold: number;
  for_minutes: number;
  severity: AlertSeverity;
  selector: RuleSelector;
  enabled: boolean;
};

/** One metric a rule may watch: its unit decides how a threshold reads. */
export type MetricInfo = {
  name: string;
  unit: "percent" | "bytes" | "seconds" | "minutes" | "count" | "ratio";
  description: string;
};

/** The rules with the vocabulary the server accepts, so a form offers only what it takes. */
export type RuleCatalogue = {
  items: AlertRule[];
  count: number;
  metrics: string[];
  catalogue?: MetricInfo[];
  operators: string[];
  severities: string[];
};

export type HostMonitoring = {
  host_id: string;
  last_sample_at?: string | null;
  latest: MetricPoint | null;
  alerts: Alert[];
  silences: Silence[];
  /** What the panel refused from this host: a hole with a cause, not a quiet machine. */
  refused: MetricRefusal[];
  clock_substitution: MetricClockSubstitution | null;
  /** How many rules select this host. */
  rules_matching: number;
};

/** A host whose agent is over the footprint budget, with the readings that put it there. */
export type FootprintHost = {
  host_id: string;
  hostname: string;
  agent_rss_bytes?: number;
  agent_cpu_percent?: number;
};

/**
 * What the agents cost the reporting hosts, from the newest sample of each.
 * A missing figure means no host reported it: an older agent sends none.
 */
export type FleetFootprint = {
  hosts_measured: number;
  rss_bytes_max?: number;
  rss_bytes_median?: number;
  cpu_percent_max?: number;
  cpu_percent_median?: number;
  helper_rss_bytes_max?: number;
  rss_budget_bytes: number;
  cpu_budget_percent: number;
  over_budget: FootprintHost[];
};

export type FleetMonitoring = {
  firing: Alert[];
  counts: { critical: number; warning: number; info: number; silenced: number; pending: number };
  hosts_reporting: number;
  hosts_silent: number;
  rules: number;
  agent_footprint?: FleetFootprint;
  generated_at: string;
};

/** What a cancel request does to an operation that is under way. */
export type CancelMode = "safe" | "checkpoint_only" | "impossible_after_start" | "local_watchdog_owned";

/** Whether repeating an operation can succeed; the same classes as the error guide. */
export type RetryClass = "never" | "automatic" | "after_change" | "after_replan" | "read_state";

/** What way back exists once the change landed. */
export type RollbackClass = "automatic_local" | "exact_restore" | "compensating" | "best_effort" | "none";

/** What a campaign checks on the host after the change. */
export type Verification = "none" | "unit_health" | "connectivity" | "plan_recheck" | "custom";

/** One claim an operation takes on a host resource. */
export type ResourceClaim = {
  class: string;
  mode: "shared" | "exclusive";
  weight: number;
};

/**
 * The second half of an operation's contract, as `/api/v1/actions` serves
 * it: what the panel may promise about an operation under way.
 */
export type OperationContract = {
  cancel_mode?: CancelMode;
  retry_class?: RetryClass;
  rollback?: RollbackClass;
  verification?: Verification;
  resource_claims?: ResourceClaim[];
};

/** The record a timeline row comes from; the screen links to its page. */
export type HostTimelineKind = "job" | "audit" | "session" | "lifecycle" | "alert" | "campaign";

/**
 * One event in the history of a host: one record of one table, cut to a
 * common shape.
 */
export type HostTimelineItem = {
  at: string;
  kind: HostTimelineKind;
  id: string;
  title: string;
  event?: string;
  detail?: string;
  state?: string;
  error_code?: string;
  actor?: string;
  ref: { type: string; id: string };
};

/** A page of the timeline; `sources` names the kinds the caller may see. */
export type HostTimelinePage = {
  items: HostTimelineItem[];
  count: number;
  next_cursor?: string;
  sources: HostTimelineKind[];
};

/** The final report of a campaign: stored once it ended, computed live before. */
export type CampaignReportOrigin = {
  stored: boolean;
  generated_at?: string;
  approval_fingerprint?: string;
  plan_set_hash?: string;
  approved_by?: string;
  created_by?: string;
};

/** The hosts of a read fan-out by state: what waits, what runs, what came back and what did not. */
export type ReadFanOutCounts = {
  queued: number;
  running: number;
  succeeded: number;
  failed: number;
};

/**
 * A diagnostic read ordered on many hosts at once. Not a campaign: nothing
 * changes and nothing is approved.
 */
export type ReadFanOut = {
  id: string;
  action: string;
  payload: Record<string, unknown>;
  created_by: string;
  reason?: string;
  created_at: string;
  host_count: number;
  counts: ReadFanOutCounts;
};

/** One host of a fan-out: its job, and what the job brought back. */
export type ReadFanOutHost = {
  job_id: string;
  host_id: string;
  hostname: string;
  state: string;
  error_code?: string;
  message?: string;
  finished_at?: string;
  truncated?: boolean;
  /** The lines of a line read, as the host gave them. */
  lines?: string[];
  /** The typed result of a structured read, as the job stored it. */
  detail?: Record<string, unknown>;
  /** The inventory state the read refreshed, for reads that answer there. */
  snapshot?: Record<string, unknown>;
};

/** One line of the merged timeline; `at` is set when the line carries a timestamp. */
export type ReadTimelineLine = {
  host_id: string;
  hostname: string;
  at?: string;
  line: string;
};

/** The lines of one host that carry no timestamp, grouped under the timeline. */
export type ReadUntimedLines = {
  host_id: string;
  hostname: string;
  lines: string[];
};

/** A matched host the fan-out did not reach, with the reason. */
export type ReadSkippedHost = {
  host_id: string;
  hostname: string;
  reason: string;
  message: string;
};

/** A fan-out with its hosts and the merged result. */
export type ReadFanOutView = ReadFanOut & {
  /** How the result merges: a timeline of lines, or a typed result per host. */
  kind: "timeline" | "structured";
  hosts: ReadFanOutHost[];
  timeline?: ReadTimelineLine[];
  untimed?: ReadUntimedLines[];
  skipped?: ReadSkippedHost[];
};

/** One step of a fleet remediation plan: a typed operation of the module that owns the finding. */
export type RemediationStep = {
  position: number;
  check_id: string;
  check_version: number;
  action_type: string;
  payload?: unknown;
  lock_class?: string;
  requires_reboot: boolean;
  state?: string;
};

/** Hosts that get the same steps: one change, however many hosts. */
export type RemediationPlanGroup = {
  plan_hash: string;
  steps: RemediationStep[];
  changes: string[];
  count: number;
  hosts: { host_id: string; hostname: string }[];
};

/** A host of the remediation snapshot that gets no plan, with the reason. */
export type RemediationExcludedHost = {
  host_id: string;
  hostname: string;
  reason: string;
  message: string;
};

/**
 * What a fleet remediation would do: the per-host plans grouped by their
 * steps, and the hosts left out.
 */
export type RemediationPreview = {
  check_ids: string[];
  hosts: number;
  eligible: number;
  groups: RemediationPlanGroup[];
  excluded: RemediationExcludedHost[];
  notes?: { reason: string; count: number; sample: string[] }[];
  generated_at: string;
};

/** The answer to a fleet remediation order: the campaign, awaiting approval, with its plan groups. */
export type RemediationOrder = {
  campaign: Campaign;
  groups: RemediationPlanGroup[];
  excluded: RemediationExcludedHost[];
};

/* ---------------------------------------------------------------------- */
/* Desired-state policies.                                                 */
/* ---------------------------------------------------------------------- */

/** The rule kinds this version of the panel judges, in the order the editor offers them. */
export type PolicyRuleKind =
  | "package_installed" | "package_absent" | "unit_state" | "file_content" | "sysctl" | "ssh_key_present";
export const POLICY_RULE_KINDS: PolicyRuleKind[] = [
  "package_installed", "package_absent", "unit_state", "file_content", "sysctl", "ssh_key_present",
];

/**
 * One typed declaration.
 */
export type PolicyRule = {
  kind: PolicyRuleKind | string;
  /** The package of package_installed and package_absent. */
  name?: string;
  /** The unit of unit_state, and the halves of its state; an absent half is undeclared. */
  unit?: string;
  enabled?: boolean;
  active?: boolean;
  /** The managed file of file_content and the digest of the version it is to hold. */
  path?: string;
  sha256?: string;
  /** The key and value of sysctl. */
  key?: string;
  value?: string;
  /** The account and the SHA256 fingerprint of ssh_key_present; the material lets the panel fix an empty account. */
  user?: string;
  fingerprint?: string;
  public_key?: string;
};

/** report writes verdicts; campaign orders a campaign that waits for approval; automatic approves it with the publication. */
export type PolicyRemediationMode = "report" | "campaign" | "automatic";
export const POLICY_MODES: PolicyRemediationMode[] = ["report", "campaign", "automatic"];

/** The four verdicts of a rule on a host; error is never compliant. */
export type PolicyVerdict = "compliant" | "drift" | "error" | "not_applicable";
export const POLICY_VERDICTS: PolicyVerdict[] = ["compliant", "drift", "error", "not_applicable"];

/** The campaign selector as a policy carries it: the same shape a campaign order takes. */
export type PolicySelector = {
  site?: string;
  environment?: string;
  os_family?: string;
  host_ids?: string[];
  expression?: SelectorExpression | null;
  exclude?: string[];
  exclude_reason?: string;
};

export type Policy = {
  id: string;
  name: string;
  description: string;
  /** The published version the loop judges by; zero for a draft never published. */
  version: number;
  selector: PolicySelector;
  rules: PolicyRule[];
  remediation_mode: PolicyRemediationMode;
  enabled: boolean;
  check_interval_seconds: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  published_at?: string;
  published_by?: string;
  last_evaluated_at?: string;
  /** The document differs from the published version; the loop judges by the published text. */
  draft: boolean;
  /** The verdicts of the latest evaluation; every verdict is a key, zero included. */
  counts: Record<PolicyVerdict, number>;
};

/** The draft as it is created and rewritten. */
export type PolicySpec = {
  name: string;
  description: string;
  selector: PolicySelector;
  rules: PolicyRule[];
  remediation_mode: PolicyRemediationMode;
  enabled: boolean;
  check_interval_seconds: number;
};

/** One publication: the frozen document and who published it, on what authentication. */
export type PolicyVersion = {
  policy_id: string;
  version: number;
  document: {
    name: string;
    description: string;
    selector: PolicySelector;
    rules: PolicyRule[];
    remediation_mode: PolicyRemediationMode;
    check_interval_seconds: number;
  };
  published_by: string;
  published_at: string;
  reason?: string;
  authentication?: string;
  acr?: string;
  amr?: string[];
  authenticated_at?: string;
};

/** The verdict of one rule on one host, with the rule the judged version carried. */
export type PolicyResult = {
  policy_id: string;
  policy_name?: string;
  host_id: string;
  hostname?: string;
  rule_index: number;
  rule?: PolicyRule;
  version: number;
  verdict: PolicyVerdict;
  /** One line; an error or an unfixable drift starts with its code. */
  reason?: string;
  observed_revision?: string;
  evaluated_at: string;
};

/** What one evaluation did. */
export type PolicyOutcome = {
  policy_id: string;
  version: number;
  hosts: number;
  counts: Record<PolicyVerdict, number>;
  campaign_id?: string;
  remediation?: string;
  evaluated_at: string;
};

/** A remediation campaign the policy ordered. */
export type PolicyCampaignLink = {
  id: string;
  name: string;
  state: string;
  policy_version: number;
  created_at: string;
};
