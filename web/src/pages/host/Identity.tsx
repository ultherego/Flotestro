import { Time, OptionalFlag, Pair, Pairs } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
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
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  return (
    <>
      <Pairs>
        <Pair label={t("In domain")}>
          {host.identity.enrolled ? <span className="badge ok">{t("yes")}</span> : <span className="badge">{t("no")}</span>}
        </Pair>
        <Pair label={t("Domain")}>{host.identity.domain || "—"}</Pair>
        <Pair label={t("Realm")}>{host.identity.realm || "—"}</Pair>
        <Pair label={t("Servers")}>{(identity.servers ?? []).join(", ") || "—"}</Pair>
        <Pair label={t("SSSD running")}>{identity.sssd_running ? t("yes") : t("no")}</Pair>
        <Pair label={t("SSSD online")}><OptionalFlag value={host.identity.sssd_online} /></Pair>
        <Pair label={t("Cache age")}>
          {identity.cache_age_seconds !== undefined
            ? `${identity.cache_age_seconds} s`
            : unknown}
        </Pair>
        <Pair label={t("Host principal")}>{identity.host_principal || unknown}</Pair>
        <Pair label={t("Keytab KVNO")}>{identity.keytab_kvno ?? unknown}</Pair>
        <Pair label={t("Clock synchronized")}>{identity.time_synchronized ? t("yes") : t("no")}</Pair>
        <Pair label={t("Checked")}><Time value={host.identity.checked_at} /></Pair>
      </Pairs>
      <ModuleFreshness fragment={module.data} />
    </>
  );
}
