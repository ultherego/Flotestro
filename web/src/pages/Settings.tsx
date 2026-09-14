import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Settings as SettingsView, SettingsArea, SettingsFact } from "../lib/types";
import { Empty, ErrorBox, Pair, Pairs } from "../components/ui";
import { Card, PageHeader } from "../components/layout";
import { useT } from "../i18n";

/**
 * The effective configuration of this panel, read-only.
 *
 * An administrator debugging a login or a stale feed asks first which
 * issuer the panel talks to and with which client, or where the feed comes
 * from and how old its data are. The answer was in the process environment
 * and nowhere on a screen. The values are set in the environment file the
 * page names; the page shows them and changes nothing - a panel that let
 * its own configuration be edited over the API would let a stolen session
 * point the login at somebody else's provider. Secrets are never shown,
 * only whether they are set.
 */
export function Settings() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<SettingsView>("/api/v1/settings"),
    retry: false,
  });

  return (
    <>
      <PageHeader
        icon="settings"
        title={t("Settings")}
        description={t("What this panel was started with. The values are set in {source} and read when the control plane starts; this screen shows them and changes nothing.", { source: data?.source ?? "/etc/flotestro/control-plane.env" })}
      />
      {error && <ErrorBox error={error} />}
      {!error && !data && <Card><Empty>{t("Loading…")}</Empty></Card>}
      {data && (
        <div className="widgets">
          {data.areas.map((area) => <AreaCard key={area.key} area={area} />)}
        </div>
      )}
    </>
  );
}

/* The titles come from the server as English keys; the catalogue turns
   them into the panel's language like every other label. */
function AreaCard({ area }: { area: SettingsArea }) {
  const t = useT();
  return (
    <Card className="span-6" title={t(area.title)}>
      <Pairs>
        {area.facts.map((fact) => (
          <Pair key={fact.key} label={t(FACT_LABELS[fact.key] ?? fact.key)}>
            <FactValue fact={fact} />
          </Pair>
        ))}
      </Pairs>
    </Card>
  );
}

function FactValue({ fact }: { fact: SettingsFact }) {
  const t = useT();
  if (fact.secret) {
    return fact.configured
      ? <span className="mono" title={t("The value is set; it is never shown here.")}>{String(fact.value)} <span className="source">{t("set")}</span></span>
      : <span className="badge unknown">{t("not set")}</span>;
  }
  const value = fact.value;
  if (value === null) return <span className="badge unknown">{t("no snapshot yet")}</span>;
  if (value === "" || (Array.isArray(value) && value.length === 0)) return <span className="source">—</span>;
  if (typeof value === "boolean") return <span className={value ? "badge ok" : "badge unknown"}>{value ? t("yes") : t("no")}</span>;
  if (Array.isArray(value)) return <span className="mono">{value.join(", ")}</span>;
  return <span className="mono">{String(value)}</span>;
}

/* The English label of each fact, so the catalogue has a sentence to
   translate rather than a key. A key without a label is shown as it is. */
const FACT_LABELS: Record<string, string> = {
  version: "Version",
  commit: "Commit",
  build_date: "Build date",
  agent_protocol: "Agent protocol",
  migration_level: "Schema migration",
  gateway_addr: "Agent gateway",
  enrollment_addr: "Enrollment endpoint",
  admin_addr: "REST API",
  advertised: "Advertised names",
  gateway_id: "Gateway identifier",
  public_url: "Public URL",
  package_repository_url: "Package repository",
  web_root: "Web root",
  state_dir: "State directory",
  heartbeat_seconds: "Heartbeat (seconds)",
  heartbeat_jitter: "Heartbeat jitter (seconds)",
  stale_after: "Stale after",
  agent_cert_ttl: "Agent certificate lifetime",
  issuer: "Issuer",
  client_id: "Client identifier",
  client_secret: "Client secret",
  groups_claim: "Groups claim",
  session_idle: "Session idle window",
  session_absolute: "Session absolute lifetime",
  configured: "Configured",
  server: "Server",
  principal: "Service principal",
  keytab: "Keytab",
  ca_certificate: "CA certificate",
  realm: "Realm",
  write_enabled: "Directory changes",
  max_age: "Maximum authentication age",
  acr: "Required level (acr)",
  tokens: "API tokens",
  production_environments: "Production environments",
  url: "URL",
  secret: "Signing secret",
  events: "Event prefixes",
  enabled: "Enabled",
  sync_interval: "Sync interval",
  max_snapshot_age: "Maximum snapshot age",
  debian_url: "Debian tracker",
  debian_snapshot_age: "Debian snapshot age",
  ubuntu_url: "Ubuntu OVAL",
  ubuntu_snapshot_age: "Ubuntu snapshot age",
  redhat_url: "Red Hat CSAF",
  redhat_snapshot_age: "Red Hat snapshot age",
  nvd_url: "NVD API",
  nvd_key: "NVD API key",
  nvd_interval: "NVD interval",
  nvd_snapshot_age: "NVD snapshot age",
  metrics_raw: "Raw resource samples",
  metrics_rollup: "Quarter-hour rollups",
  audit: "Audit trail",
  secrets_key_file: "Secret store key file",
};
