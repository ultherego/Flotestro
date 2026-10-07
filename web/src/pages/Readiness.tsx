import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type { FleetReadiness, ReadinessGap } from "../lib/types";
import { ErrorBox, Empty } from "../components/ui";
import { Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { useT } from "../i18n";

/**
 * What stands between this fleet and being managed.
 *
 * The panel could already answer "who can carry out this operation" - that is
 * the campaign preview. This is the transpose, which nothing answered: for the
 * fleet as a whole, what cannot be carried out and why. Grouped by the cause
 * rather than by the host, because three hosts without a Docker Compose plugin
 * are one thing to fix and not three.
 *
 * The reason beside each host is the agent's own sentence. It is the remedy as
 * well as the diagnosis: "this host has no Docker Compose plugin" says what to
 * install.
 */
/**
 * What the head of the screen has to say about a fleet.
 *
 * The case worth holding is the third one: no gaps found and hosts that have
 * reported no adapter at all. A fleet whose hosts said nothing is not a fleet
 * without gaps, and a screen that showed a green zero there would be the
 * "unknown is not zero" fault committed by the panel itself, about the very
 * thing it exists to surface.
 */
export type ReadinessVerdict = "ok" | "unknown" | "attention";

export function readinessVerdict(data: {
  silent: number;
  unorderable: number;
  gaps: { nowhere: boolean }[];
}): ReadinessVerdict {
  if (data.unorderable > 0 || data.gaps.some((gap) => gap.nowhere)) return "attention";
  if (data.silent > 0) return "unknown";
  return data.gaps.length > 0 ? "attention" : "ok";
}

export default function Readiness() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["fleet-readiness"],
    queryFn: () => api.get<FleetReadiness>("/api/v1/fleet/readiness"),
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const nowhere = data.gaps.filter((gap) => gap.nowhere);
  const somewhere = data.gaps.filter((gap) => !gap.nowhere);
  const verdict = readinessVerdict(data);

  return (
    <>
      <PageHeader title={t("Readiness")} />
      <Card>
        <FieldGrid>
          <Field label={t("hosts")}>{data.hosts}</Field>
          {/* A fleet whose hosts have said nothing is not a fleet without
              gaps, and the number says so rather than leaving a quiet zero. */}
          <Field label={t("silent about their adapters")}>
            {data.silent > 0 ? <span className="badge unknown">{data.silent}</span> : 0}
          </Field>
          <Field label={t("operations that need an adapter")}>{data.operations}</Field>
          <Field label={t("orderable nowhere")}>
            {data.unorderable > 0 ? <span className="badge warn">{data.unorderable}</span> : 0}
          </Field>
        </FieldGrid>
      </Card>

      {data.gaps.length === 0 && verdict === "ok" && (
        <Empty>{t("Every operation can be ordered on every host of this fleet.")}</Empty>
      )}
      {data.gaps.length === 0 && verdict === "unknown" && (
        <Empty>
          {t("No gap was found, and some hosts have reported no adapter at all - so this is not the same as a fleet with nothing missing.")}
        </Empty>
      )}

      {nowhere.length > 0 && (
        <Card title={t("Nowhere in this fleet")}>
          <p className="source">
            {t("No visible host offers what these operations need, so ordering one would be refused everywhere.")}
          </p>
          <Gaps gaps={nowhere} />
        </Card>
      )}

      {somewhere.length > 0 && (
        <Card title={t("On some hosts")}>
          <p className="source">
            {t("Other hosts offer these, so an operation reaches part of the fleet. A host of another family is often a reason rather than a fault.")}
          </p>
          <Gaps gaps={somewhere} />
        </Card>
      )}
    </>
  );
}

/**
 * One row per cause, which is the whole point of the screen.
 *
 * The first version gave every requirement a table of its own, with the column
 * headings repeated and the same sentence - "this host has no Docker socket" -
 * written once per host. That is grouping by host wearing the clothes of
 * grouping by cause. The reason is said once when every host gave the same
 * one, which is the ordinary case, and per host only when they differ.
 */
function Gaps({ gaps }: { gaps: ReadinessGap[] }) {
  const t = useT();
  // One open at a time, and the list opens in a row of its own below rather
  // than inside the cell: pushing the cell made the row grow and everything
  // under it jump, which is a poor way to read a list somebody opened on
  // purpose.
  const [open, setOpen] = useState("");
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">{t("what is missing")}</th>
          <th scope="col">{t("work it blocks")}</th>
          <th scope="col">{t("on")}</th>
          <th scope="col">{t("what the host said")}</th>
        </tr>
      </thead>
      <tbody>
        {gaps.map((gap) => (
          <GapRow
            key={gap.requirement}
            gap={gap}
            open={open === gap.requirement}
            onToggle={() => setOpen((current) => current === gap.requirement ? "" : gap.requirement)}
          />
        ))}
      </tbody>
    </table>
  );
}

function GapRow({ gap, open, onToggle }: {
  gap: ReadinessGap;
  open: boolean;
  onToggle: () => void;
}) {
  const t = useT();
  const reasons = new Set(gap.hosts.map((host) => host.silent ? "" : host.reason || ""));
  const shared = reasons.size === 1 ? [...reasons][0] : "";
  const silent = gap.hosts.filter((host) => host.silent).length;
  return (
    <>
      <tr>
        <td><code>{gap.requirement}</code></td>
        <td>
          <button
            type="button"
            className="expander"
            aria-expanded={open}
            aria-label={open
              ? t("Hide the operations {requirement} blocks", { requirement: gap.requirement })
              : t("Show the operations {requirement} blocks", { requirement: gap.requirement })}
            onClick={onToggle}
          >
            {open ? "▾" : "▸"}
          </button>{" "}
          {count(t, gap.operations.length, "operation", "operations")}
        </td>
        <td>
          {gap.hosts.map((host, index) => (
            <span key={host.id}>
              {index > 0 && ", "}
              <Link to={`/hosts/${host.id}`}>{host.hostname}</Link>
            </span>
          ))}
          {gap.satisfied > 0 && (
            <div className="source">{count(t, gap.satisfied, "host offers it", "hosts offer it")}</div>
          )}
        </td>
        <td>
          {silent === gap.hosts.length && silent > 0
            ? <span className="badge unknown">{t("has reported no adapter at all")}</span>
            : shared
              ? shared
              : gap.hosts.map((host) => (
                  <div key={host.id}>
                    <span className="source">{host.hostname}: </span>
                    {host.silent
                      ? <span className="badge unknown">{t("has reported no adapter at all")}</span>
                      : host.reason || <span className="badge unknown">{t("gave no reason")}</span>}
                  </div>
                ))}
        </td>
      </tr>
      {open && (
        <tr className="detail-row">
          <td colSpan={4}>
            {/* Columns rather than one long line and rather than one name per
                row: fifteen operation names read as a list at a glance and as
                neither of the other two. */}
            <ul className="fp-op-grid">
              {gap.operations.map((operation) => <li key={operation}><code>{operation}</code></li>)}
            </ul>
          </td>
        </tr>
      )}
    </>
  );
}

/** One or many, because "1 hosts" is how a screen tells you nobody read it. */
function count(t: (text: string) => string, value: number, one: string, many: string) {
  return `${value} ${t(value === 1 ? one : many)}`;
}
