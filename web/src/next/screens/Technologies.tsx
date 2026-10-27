import { useMemo } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { Host } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Button, C, Card, Download, Empty, Grid, Kpi, Kpis, Note, Pill, Problem, Table,
} from "../kit";

/**
 * The technologies of the fleet: for each one, the hosts that have it and the hosts that do not.
 *
 * A campaign is built for the hosts a technology is on, so the question comes before it: which
 * hosts run Docker, which cannot, and which never said. The third group is kept apart because a
 * host that did not report an adapter is not a host without it. The list that is read here is
 * handed to the campaign as a selector, not as a copy, so it follows the fleet.
 */

/** One technology as the fleet counts it. */
export type FleetCapability = {
  name: string;
  available: number;
  missing: number;
  unknown: number;
  reasons: { key: string; count: number }[];
};

type FleetCapabilities = { total: number; items: FleetCapability[] };

/** The technologies a host reports, in the order the fleet is usually asked about. */
export const TECHNOLOGIES = [
  "docker", "docker.compose", "firewall", "network", "dns", "systemd", "journald", "packages.apt",
  "packages.dnf", "packages.pacman", "schedules", "storage", "sshd", "kernel", "files.managed",
];

/** How many hosts of one answer the screen draws; the rest is behind the host list. */
export const LIST_LIMIT = 100;

/** The campaign wizard, opened on the hosts that have a technology (a selector, not a list). */
export function campaignFor(technology: string): string {
  return `/bulk?capability=${encodeURIComponent(technology)}`;
}

/** The host list narrowed to one answer about one technology. */
export function hostsWhere(technology: string, state: "available" | "missing" | "unknown"): string {
  return `/hosts?capability=${encodeURIComponent(technology)}&capability_state=${state}`;
}

/**
 * The fleet's rows for the technologies it knows: one for every name a host reported, and one
 * for the names none has, which are all unknown rather than all absent.
 */
export function withEveryTechnology(fleet: FleetCapabilities | undefined): FleetCapability[] {
  const total = fleet?.total ?? 0;
  const known = new Map((fleet?.items ?? []).map((one) => [one.name, one]));
  const names = [...TECHNOLOGIES, ...[...known.keys()].filter((name) => !TECHNOLOGIES.includes(name))];
  return names.map((name) => known.get(name) ?? { name, available: 0, missing: 0, unknown: total, reasons: [] });
}

export function Technologies() {
  const t = useT();
  const [address] = useSearchParams();
  const fleet = useQuery({
    queryKey: ["fleet-capabilities"],
    queryFn: () => api.get<FleetCapabilities>("/api/v1/fleet/capabilities"),
    staleTime: 30_000,
  });
  const rows = useMemo(() => withEveryTechnology(fleet.data), [fleet.data]);
  const asked = address.get("technology") ?? "";
  const chosen = rows.find((one) => one.name === asked) ?? rows.find((one) => one.name === "docker") ?? rows[0];
  const total = fleet.data?.total;

  if (fleet.error) return <Problem>{fleet.error instanceof ApiError ? fleet.error.message : String(fleet.error)}</Problem>;

  return (
    <>
      <Kpis>
        <Kpi hero icon="hosts" label={t("Hosts")} value={total ?? null} note={t("you may read, not retired")} />
        <Kpi
          icon="containers"
          label={chosen ? t("Have {name}", { name: chosen.name }) : t("Have it")}
          value={chosen && total !== undefined ? chosen.available : null}
          note={chosen && total !== undefined ? t("of {total} hosts", { total }) : undefined}
        />
        <Kpi
          icon="overview"
          label={t("Never said")}
          value={chosen && total !== undefined ? chosen.unknown : null}
          note={t("an agent that did not report it is not a host without it")}
        />
      </Kpis>
      <Grid>
        <C span={5}>
          <Card title={t("Technologies")} note={t("Choose one to see who has it.")} flush>
            <Table
              rows={rows}
              keyOf={(one) => one.name}
              rowTestId={(one) => `technology-${one.name}`}
              empty={fleet.isLoading ? t("Reading the fleet…") : t("No host has reported a technology yet.")}
              columns={[
                { key: "name", head: t("Technology"), tight: true, cell: (one) => (
                  <Link to={`/technologies?technology=${encodeURIComponent(one.name)}`} replace>{one.name}</Link>
                ) },
                { key: "have", head: t("Have"), num: true, cell: (one) => one.available },
                { key: "missing", head: t("Cannot"), num: true, cell: (one) => one.missing },
                { key: "unknown", head: t("Never said"), num: true, minor: true, cell: (one) => one.unknown },
              ]}
            />
          </Card>
        </C>
        <C span={7}>
          {chosen && total !== undefined && <Chosen technology={chosen} total={total} />}
        </C>
      </Grid>
    </>
  );
}

/** One technology: the two (three) lists, the reasons and the way into a campaign. */
function Chosen({ technology, total }: { technology: FleetCapability; total: number }) {
  const t = useT();
  const navigate = useNavigate();
  const name = technology.name;
  const noOne = technology.available === 0;
  return (
    <Grid>
      <C span={12}>
        <Card
          title={t("Hosts with {name}", { name })}
          note={t("{n} of {total}", { n: technology.available, total })}
          tools={
            <>
              <Download
                path="/api/v1/hosts"
                params={new URLSearchParams({ capability: name, capability_state: "available" })}
                label={t("Export the list")}
                disabled={noOne}
              />
              <Button
                onClick={() => navigate(campaignFor(name))}
                disabled={noOne}
                testId="technology-campaign"
                title={t("The campaign takes the technology as its selector, so it follows the fleet.")}
              >
                {t("Use as campaign targets")}
              </Button>
            </>
          }
          flush
        >
          <HostsOf technology={name} state="available" count={technology.available} />
        </Card>
      </C>
      <C span={12}>
        <Card
          title={t("Hosts that cannot use {name}", { name })}
          note={t("{n} reported it unusable", { n: technology.missing })}
          flush
        >
          {technology.reasons.length > 0 && (
            <Table
              rows={technology.reasons}
              keyOf={(one) => one.key}
              rowTestId={(one) => `reason-${one.key}`}
              columns={[
                { key: "reason", head: t("Reason given"), cell: (one) => (one.key === "-" ? t("no reason given") : one.key) },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.count },
              ]}
            />
          )}
          <HostsOf technology={name} state="missing" count={technology.missing} />
        </Card>
      </C>
      {technology.unknown > 0 && (
        <C span={12}>
          <Card
            title={t("Hosts that never reported {name}", { name })}
            note={t("{n} — not the same as hosts without it", { n: technology.unknown })}
            flush
          >
            <Note>
              {t("These hosts have not said whether they have {name}: an agent older than the technology, or a host not yet seen. A campaign does not reach them.", { name })}
            </Note>
            <HostsOf technology={name} state="unknown" count={technology.unknown} />
          </Card>
        </C>
      )}
    </Grid>
  );
}

/** The first hosts of one answer; the host list holds the rest. */
function HostsOf({ technology, state, count }: {
  technology: string;
  state: "available" | "missing" | "unknown";
  count: number;
}) {
  const t = useT();
  const list = useQuery({
    queryKey: ["fleet-capability-hosts", technology, state],
    queryFn: () => api.get<Collection<Host>>(
      `/api/v1/hosts?limit=${LIST_LIMIT}&capability=${encodeURIComponent(technology)}&capability_state=${state}`),
    enabled: count > 0,
  });
  const items = list.data?.items ?? [];
  if (count === 0) return <Empty>{t("No host.")}</Empty>;
  return (
    <>
      <Table
        rows={items}
        keyOf={(one) => one.id}
        rowTestId={(one) => `host-${state}-${one.hostname}`}
        empty={list.isLoading ? t("Reading the hosts…") : t("No host.")}
        columns={[
          { key: "host", head: t("Host"), tight: true, cell: (one) => <Link to={`/hosts/${one.id}`}>{one.hostname}</Link> },
          { key: "site", head: t("Site"), tight: true, minor: true, cell: (one) => one.site || "—" },
          { key: "environment", head: t("Environment"), tight: true, minor: true, cell: (one) => one.environment || "—" },
          { key: "state", head: t("Connection"), cell: (one) => (
            <Pill tone={one.connection_state === "online" ? "ok" : "unknown"}>{one.connection_state}</Pill>
          ) },
        ]}
      />
      {count > items.length && items.length > 0 && (
        <Note>
          {t("{shown} of {n} hosts are drawn.", { shown: items.length, n: count })}{" "}
          <Link to={hostsWhere(technology, state)}>{t("All of them in the host list")}</Link>
        </Note>
      )}
    </>
  );
}

