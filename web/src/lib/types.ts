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
  // What operators recorded about the host: "key" or "key=value". Always a
  // list; a host without tags has an empty one.
  tags: string[];
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

/**
 * One node of a campaign selector: exactly one field is set. A combinator
 * holds other nodes; a leaf names one fact about the host. The server
 * compiles it into the host query, so the panel never resolves it itself.
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
};

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
  // A missing one is a counter the server could not answer honestly for
  // this view, and the tile is left out rather than shown as zero.
  failed_jobs_24h?: number;
  pending_enrollment_requests?: number;
  agents_behind_latest?: number;
  latest_agent_version?: string;
  agent_certificates_expiring?: number;
  degraded_relays?: number;
};

export type Job = {
  id: string;
  host_id: string;
  hostname?: string;
  campaign_id?: string;
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
  campaign_id: string;
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
 * The effective access of one host. `known` false means the directory has
 * no entry for the host: the rules that reach it are then undetermined,
 * not absent.
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
  bindings?: { role: string; scope: { site: string; environment: string } }[];
  /** The live API tokens; the value of a token is never among them. */
  tokens?: ApiToken[];
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

/** One stage of an installation, as the panel really sees it. */
export type EnrollmentStepState = "waiting" | "done" | "failed";

export type EnrollmentStep = {
  key: "token" | "certificate" | "connected" | "inventory";
  state: EnrollmentStepState;
  // The reason the step does not go on, when the panel knows it: a refused
  // attempt recorded against the order, or a readiness gate the host has
  // not passed in time. Absent when the panel knows nothing yet.
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

/** A relay of a site: the route of an installation in an isolated site. */
export type Relay = {
  id: string;
  name: string;
  site: string;
  environment?: string;
  not_after?: string;
  enrolled_at: string;
  last_seen_at?: string;
  revoked_at?: string;
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
 * Everything a host needs before it holds a token. Nothing here is secret,
 * so the profile is read for a placement and as often as needed; the token
 * is ordered separately and shown once.
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
 * One sample of a host, or one rollup step of them. A rollup carries the
 * peak of the step beside the mean, so a short spike within a quarter of
 * an hour is not averaged away.
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
  cpu_percent_max?: number;
  memory_used_max?: number;
};

export type HostMetrics = {
  host_id: string;
  range: MetricRange;
  /** 60 for raw samples, 900 for the rollups of the long windows. */
  step_seconds: number;
  points: MetricPoint[];
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
  host_id: string;
  hostname: string;
  /** Empty when the silence covers every rule of the host. */
  rule_id?: string | null;
  rule_name?: string | null;
  until: string;
  reason: string;
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

/** The rules with the vocabulary the server accepts, so a form offers only what it takes. */
export type RuleCatalogue = {
  items: AlertRule[];
  count: number;
  metrics: string[];
  operators: string[];
  severities: string[];
};

export type HostMonitoring = {
  host_id: string;
  last_sample_at?: string | null;
  latest: MetricPoint | null;
  alerts: Alert[];
  silences: Silence[];
  /** How many rules select this host. */
  rules_matching: number;
};

export type FleetMonitoring = {
  firing: Alert[];
  counts: { critical: number; warning: number; info: number; silenced: number; pending: number };
  hosts_reporting: number;
  hosts_silent: number;
  rules: number;
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
 * it: what the panel may promise about an operation under way. The cancel
 * button, the stop confirmation and the rollback link are drawn from
 * these, never from the operation name.
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
 * common shape. `event` is the moment of the record the row stands for
 * (a task created or finished, a session opened or ended); `state` and
 * `error_code` are the record's own.
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
