import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Host, HostAccess } from "../../lib/types";
import { Time, OptionalFlag } from "../../components/ui";
import { Fact, Facts, Foot, ModuleFreshness, ModuleHeader, ModulePage, Section, Table, Unknown, useHost, useModule } from "./shared";
import { useT } from "../../i18n";

type IdentityState = {
  servers?: string[];
  sssd_running?: boolean;
  cache_age_seconds?: number;
  host_principal?: string;
  keytab_kvno?: number;
  time_synchronized?: boolean;
  unavailable_reason?: string;
};

export function Identity() {
  const t = useT();
  const host = useHost();
  const module = useModule<IdentityState>(host.id, "identity");
  const identity = module.data?.payload ?? {};

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Identity")}
        description={t("Domain membership and the directory client, as the host last checked them.")}
      />
      <ModuleFreshness fragment={module.data} />

      <Section title={t("Domain")} flush>
        <Facts>
          <Fact label={t("In domain")}>
            {host.identity.enrolled ? <span className="badge ok">{t("yes")}</span> : <span className="badge">{t("no")}</span>}
          </Fact>
          <Fact label={t("Domain")}>{host.identity.domain || "—"}</Fact>
          <Fact label={t("Realm")}>{host.identity.realm || "—"}</Fact>
          <Fact label={t("Servers")}><span className="hm-mono">{(identity.servers ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Host principal")}>
            {identity.host_principal ? <span className="hm-mono">{identity.host_principal}</span> : <Unknown />}
          </Fact>
          <Fact label={t("Keytab KVNO")}>{identity.keytab_kvno ?? <Unknown />}</Fact>
        </Facts>
      </Section>

      <Section title={t("Directory client")} flush>
        <Facts>
          <Fact label={t("SSSD running")}>{identity.sssd_running ? t("yes") : t("no")}</Fact>
          <Fact label={t("SSSD online")}><OptionalFlag value={host.identity.sssd_online} /></Fact>
          <Fact label={t("Cache age")}>
            {identity.cache_age_seconds !== undefined
              ? `${identity.cache_age_seconds} s`
              : <Unknown />}
          </Fact>
          <Fact label={t("Clock synchronized")}>{identity.time_synchronized ? t("yes") : t("no")}</Fact>
          <Fact label={t("Checked")}><Time value={host.identity.checked_at} /></Fact>
        </Facts>
      </Section>

      <EffectiveAccess host={host} />
    </ModulePage>
  );
}

/**
 * The effective access: the host's groups and the access and sudo rules
 * that reach it, as the directory holds them. Nothing here is decided by
 * the panel - the host's SSSD applies the rules - so the section shows the
 * projection and says plainly when it could not be read. An unavailable
 * directory or a host the directory does not know is "unknown", never "no
 * access".
 */
function EffectiveAccess({ host }: { host: Host }) {
  const t = useT();
  const access = useQuery({
    queryKey: ["host-access", host.id],
    queryFn: () => api.get<HostAccess>(`/api/v1/hosts/${host.id}/access`),
    retry: false,
  });

  if (access.error) {
    const error = access.error;
    const detail = error instanceof ApiError && error.status === 501
      ? t("No directory connector is configured; the panel cannot tell which rules reach this host.")
      : error instanceof ApiError && error.forbidden
        ? t("You do not have permission to read the directory.")
        : t("The directory did not answer: {error}", { error: error instanceof Error ? error.message : String(error) });
    return (
      <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules say.")}>
        <p className="hm-message"><Unknown /> {detail}</p>
      </Section>
    );
  }

  const data = access.data;
  if (!data) {
    return (
      <Section title={t("Effective access")}>
        <p className="hm-message">{t("Reading the directory…")}</p>
      </Section>
    );
  }
  if (!data.known) {
    return (
      <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules say.")}>
        <p className="hm-message"><Unknown /> {data.detail}</p>
      </Section>
    );
  }

  return (
    <>
      <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules say.")} flush>
        <Facts>
          <Fact label={t("Directory entry")}><span className="hm-mono">{data.fqdn}</span></Fact>
          <Fact label={t("Enrolled in the directory")}>
            {data.enrolled ? <span className="badge ok">{t("yes")}</span> : <span className="badge">{t("no")}</span>}
          </Fact>
          <Fact label={t("Host groups")} wide>{data.host_groups.join(", ") || t("none")}</Fact>
        </Facts>
      </Section>

      <Section title={t("HBAC rules reaching this host")} count={data.hbac_rules.length} flush>
        <Table>
          <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Via")}</th><th>{t("Who")}</th><th>{t("Services")}</th></tr></thead>
          <tbody>
            {data.hbac_rules.length === 0 ? (
              <tr><td colSpan={5} className="empty">{t("No HBAC rule reaches this host: nobody from the directory can sign in.")}</td></tr>
            ) : data.hbac_rules.map((rule) => (
              <tr key={rule.name}>
                <td>
                  {rule.name}
                  {rule.allows_everything && <> <span className="badge error">{t("covers the whole fleet")}</span></>}
                </td>
                <td>{rule.enabled ? t("yes") : <span className="badge">{t("no")}</span>}</td>
                <td>{rule.via.join(", ")}</td>
                <td>
                  {rule.all_users
                    ? t("every user")
                    : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}
                </td>
                <td>{rule.all_services ? t("every service") : [...(rule.services ?? []), ...(rule.service_groups ?? [])].join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </Table>
        <Foot>{t("A disabled rule is listed because it would apply the moment somebody enables it.")}</Foot>
      </Section>

      <Section title={t("sudo rules reaching this host")} count={data.sudo_rules.length} flush>
        <Table>
          <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Via")}</th><th>{t("Who")}</th><th>{t("Commands")}</th><th>{t("Run as")}</th><th>{t("Risk")}</th></tr></thead>
          <tbody>
            {data.sudo_rules.length === 0 ? (
              <tr><td colSpan={7} className="empty">{t("No sudo rule from the directory reaches this host.")}</td></tr>
            ) : data.sudo_rules.map((rule) => (
              <tr key={rule.name}>
                <td>{rule.name}</td>
                <td>{rule.enabled ? t("yes") : <span className="badge">{t("no")}</span>}</td>
                <td>{rule.via.join(", ")}</td>
                <td>
                  {rule.all_users
                    ? t("every user")
                    : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}
                </td>
                <td className="hm-mono">{rule.all_commands ? t("every command") : [...(rule.commands ?? []), ...(rule.command_groups ?? [])].join(", ") || "—"}</td>
                <td>{rule.run_as_any_user ? t("any user") : [...(rule.run_as ?? []), ...(rule.run_as_groups ?? [])].join(", ") || "—"}</td>
                <td>
                  {rule.critical
                    ? <span className="badge error" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</span>
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
        <Foot>{t("Local sudoers entries on the host are not part of this list; only what the directory grants.")}</Foot>
      </Section>
    </>
  );
}
