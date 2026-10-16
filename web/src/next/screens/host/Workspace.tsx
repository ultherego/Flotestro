import { useParams } from "react-router-dom";

import { useQuery } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useCapabilities } from "../../../lib/capabilities";
import { DEFAULT_MODULE, groupedModules, module as moduleOf, modules } from "../../../lib/modules";
import { REFRESH_INTERVAL } from "../../../lib/stream";
import { relativeTime, absoluteTime } from "../../../lib/format";
import type { Host } from "../../../lib/types";
import { useT } from "../../../i18n";
import { Shell, type Face } from "../../Shell";
import {
  Empty, Head, Pill, Problem, Tag, Tags, type Tone,
} from "../../kit";
import { HOST_MODULES } from "./modules";

/**
 * One machine, and everything the panel can say or do about it.
 *
 * The rail stops being the fleet here and becomes this host's modules,
 * grouped the way the registry groups them, with the way back at the top.
 * A module this host has no backing for stays listed and says why: left
 * out, it reads as a panel that forgot it exists.
 */

/** The module named in the address, drawn with the host it is about. */
function Module({ module, host }: { module: string; host: Host }) {
  const Drawn = HOST_MODULES[module];
  return Drawn ? <Drawn host={host} /> : null;
}

export function HostWorkspace() {
  const t = useT();
  const { id = "", module = DEFAULT_MODULE } = useParams();
  const installation = useCapabilities();

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    // The head carries the connection state, so it refreshes itself: a
    // stale answer to "is this machine there" is worse than none.
    refetchInterval: REFRESH_INTERVAL,
  });

  const data = host.data;
  const entry = moduleOf(module);
  const face: Face = {
    back: { to: "/next/hosts", label: "All hosts" },
    groups: data
      ? groupedModules(modules(data, installation)).map((group) => ({
          key: group.key,
          label: group.title,
          items: group.items.map((one) => ({
            to: `/next/hosts/${id}/${one.segment}`,
            label: one.name,
            icon: one.icon,
            unavailable: one.available ? undefined : one.missingReason,
          })),
        }))
      : [],
  };

  return (
    <Shell trail={{ section: "Hosts", to: "/next/hosts", here: data?.hostname }} face={face}>
      {host.error ? <Problem>{String(host.error)}</Problem> : !data ? <Empty>{t("Loading…")}</Empty> : (
        <>
          <HostHead host={data} />
          {HOST_MODULES[module] ? <Module module={module} host={data} /> : (
            <>
              <Head
                title={t(entry?.name ?? module)}
                lead={t("This module is still being rewritten.")}
              />
              <Empty action={<a className="fl-btn fl-quiet" href={`/hosts/${id}/${module}`}>{t("Open it in the panel as it is")}</a>}>
                {t("The new panel is being written screen by screen; this one has not been reached yet.")}
              </Empty>
            </>
          )}
        </>
      )}
    </Shell>
  );
}

/**
 * Which machine this is, in one band: its name, whether it answers, where
 * it stands and what it runs. Everything a reader needs to be sure they
 * are looking at the host they meant.
 */
function HostHead({ host }: { host: Host }) {
  const t = useT();
  const tone: Tone = host.connection_state === "online" ? "ok"
    : host.connection_state === "offline" ? "error"
    : host.connection_state === "stale" ? "warn" : "unknown";
  return (
    <Head
      title={host.hostname}
      lead={
        <Tags>
          <Pill tone={tone} title={host.last_seen_at ? absoluteTime(host.last_seen_at) : undefined}>
            {t(host.connection_state)}
          </Pill>
          <Tag>{host.management_address || t("address unknown")}</Tag>
          <Tag>{host.site} / {host.environment}</Tag>
          <Tag>
            {host.os_distribution || host.os_family || t("unknown")}
            {host.os_version ? ` ${host.os_version}` : ""}
          </Tag>
          <Tag>{host.architecture || t("unknown arch")} · {t("agent {version}", { version: host.agent_version || t("unknown") })}</Tag>
          {host.last_seen_at && (
            <Tag>{t("seen")} {relativeTime(host.last_seen_at)}</Tag>
          )}
          {host.tags.length > 0
            ? host.tags.map((tag) => (
                <Tag key={tag} to={`/next/hosts?tag=${encodeURIComponent(tag)}`}>{tag}</Tag>
              ))
            : <Tag>{t("no tags")}</Tag>}
        </Tags>
      }
      actions={<a className="fl-btn fl-quiet" href={`/hosts/${host.id}`}>{t("Open in the panel as it is")}</a>}
    />
  );
}
