import { Time, OptionalFlag } from "../../components/ui";
import { Fact, Facts, ModuleFreshness, ModuleHeader, ModulePage, Section, Unknown, useHost, useModule } from "./shared";
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
    </ModulePage>
  );
}
