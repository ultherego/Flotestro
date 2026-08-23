// Typy odpowiadaja kontraktowi REST control plane.

/**
 * Adapter wykryty na hoscie. Nazwa mowi, co host ma ("packages.apt"), a nie
 * czego chce operacja ("packages"). Powod pochodzi z hosta: interfejs ma go
 * powtorzyc, a nie zgadywac przyczyne we wlasnym kodzie.
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
 * Stan jednego modulu inventory. Rewizja i znacznik obserwacji sa wlasne dla
 * modulu, wiec zakladka pokazuje swiezosc tego, co wyswietla.
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
  // Puste wartosci oznaczaja stan nieustalony, nie zero.
  reboot_required: boolean | null;
  failed_units: number | null;
  pending_updates: number | null;
  pending_security_updates: number | null;
  current_inventory_revision?: string;
  package_database_broken: boolean;
  // Adres zarzadzania i jego pochodzenie. Brak wartosci oznacza adres
  // nieustalony i musi byc pokazany jako nieustalony.
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
  created_by: string;
  approved_by?: string;
  paused_by?: string;
  pause_reason?: string;
  created_at: string;
};

export type CampaignTarget = {
  host_id: string;
  hostname?: string;
  wave: number;
  state: string;
  error_code?: string;
  message?: string;
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
  /** Uprawnienia w dowolnym zakresie; interfejs ukrywa nimi sekcje bez pokrycia. */
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
 * Konto widziane na hoscie. Wartosc null oznacza stan nieustalony i musi byc
 * pokazana jako nieznana, a nie jako "nie" - inaczej panel twierdzilby, ze
 * konto ma otwarty dostep, choc tego nie sprawdzil.
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
  /** Moze nie przyjsc: tozsamosc bez wlasnych przypisan ma role z mapowan grup. */
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
 * CA floty. Stan "pending" znaczy, ze CA jest juz uznawane i rozsylane, ale
 * jeszcze nie podpisuje - przekazanie mu podpisywania wymaga, zeby cala flota
 * zdazyla je poznac.
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
