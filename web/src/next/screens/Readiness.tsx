import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { FleetReadiness, ReadinessGap } from "../../lib/types";
import { readinessVerdict, type ReadinessVerdict } from "../../lib/readiness";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Banner, Card, Empty, Kpi, Pill, Problem, Stack, Table, Tag, Tags, type Tone, TwoLine,
} from "../kit";

/**
 * What this fleet cannot be asked to do, and why.
 *
 * The panel could already answer "who can carry out this operation" - that
 * is the campaign preview. This is the transpose, grouped by the cause and
 * not by the host, because three hosts without a Docker Compose plugin are
 * one thing to fix and not three.
 *
 * It is also the screen where "unknown is not nought" is shown to the
 * operator rather than only enforced inside the modules. A host that has
 * reported no adapter has not reported an empty one, so it never counts
 * towards a clean fleet: the verdict goes to unknown and says so.
 */

/** The verdict as a tone: a fleet nobody has asked is not a fleet that passed. */
export function verdictTone(verdict: ReadinessVerdict): Tone {
  return verdict === "ok" ? "ok" : verdict === "unknown" ? "unknown" : "warn";
}

export function Readiness() {
  const t = useT();
  const view = useQuery({
    queryKey: ["fleet-readiness"],
    queryFn: () => api.get<FleetReadiness>("/api/v1/fleet/readiness"),
  });

  // Which requirement the reader asked to see the work of. One at a time,
  // and it lands in a card of its own rather than inside the cell: opening
  // a list of fifteen operation names inside a row pushed everything under
  // it down the screen, which is a poor way to read something opened on
  // purpose.
  const [opened, setOpened] = useState("");

  if (view.error) return <Problem>{String(view.error)}</Problem>;

  const data = view.data;
  const gaps = data?.gaps ?? [];
  const nowhere = gaps.filter((one) => one.nowhere);
  const somewhere = gaps.filter((one) => !one.nowhere);
  const verdict = data ? readinessVerdict(data) : undefined;
  const chosen = gaps.find((one) => one.requirement === opened);

  return (
    <>
      
      <Board
        screen={READINESS_SCREEN}
        catalogue={READINESS}
        notices={
          <Banner tone={verdict ? verdictTone(verdict) : "unknown"}>
            {!data || !verdict
              ? t("Asking the fleet what it can be sent…")
              : verdict === "ok"
                ? t("Every operation can be ordered on every host of this fleet.")
                : verdict === "unknown"
                  ? t("No gap was found, and some hosts have reported no adapter at all - so this is not the same as a fleet with nothing missing.")
                  : (
                    <>
                      {t("{gaps} requirements are not met everywhere, and {n} operations can be ordered on no visible host.", { gaps: gaps.length, n: data.unorderable })}
                      {/* Attention outranks unknown, so the silent hosts
                          would otherwise go unsaid on the very screen that
                          exists to say them. */}
                      {data.silent > 0 && ` ${t("{n} hosts have reported no adapter at all, so this is not the whole of it.", { n: data.silent })}`}
                    </>
                  )}
          </Banner>
        }
        drawn={{
        hosts: (
          <Kpi
            hero
            icon="hosts"
            label={t("Hosts")}
            value={data?.hosts ?? null}
            note={t("every host this installation can see")}
          />
        ),
        silent: (
          <Kpi
            icon="overview"
            label={t("Silent about their adapters")}
            value={data?.silent ?? null}
            tone={data && data.silent > 0 ? "unknown" : "ok"}
            note={t("a host that said nothing is not a host with nothing missing")}
          />
        ),
        operations: (
          <Kpi
            icon="bulk"
            label={t("Operations that need an adapter")}
            value={data?.operations ?? null}
            note={t("of the whole catalogue")}
          />
        ),
        unorderable: (
          <Kpi
            icon="campaigns"
            label={t("Orderable nowhere")}
            value={data?.unorderable ?? null}
            tone={data && data.unorderable > 0 ? "error" : "ok"}
            note={t("ordering one of these would be refused everywhere")}
          />
        ),
        nowhere: nowhere.length > 0 && (
          <Card
            title={t("Nowhere in this fleet")}
            note={t("No visible host offers what these operations need, so ordering one would be refused everywhere.")}
            flush
          >
            <Gaps gaps={nowhere} opened={opened} onOpen={setOpened} testId="gaps-nowhere" />
          </Card>
        ),
        somewhere: somewhere.length > 0 && (
          <Card
            title={t("On some hosts")}
            note={t("Other hosts offer these, so an operation reaches part of the fleet. A host of another family is often a reason rather than a fault.")}
            flush
          >
            <Gaps gaps={somewhere} opened={opened} onOpen={setOpened} testId="gaps-somewhere" />
          </Card>
        ),
        blocked: (
          <Card
            title={t("What it blocks")}
            note={chosen ? chosen.requirement : t("Pick a requirement above.")}
          >
            {chosen
              ? (
                <Tags>
                  {chosen.operations.map((one) => <Tag key={one}><code>{one}</code></Tag>)}
                </Tags>
              )
              : <Empty>{t("The operations a missing requirement blocks are listed here.")}</Empty>}
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * One row per cause, which is the whole point of the screen.
 *
 * The first version of this gave every requirement a table of its own,
 * with the headings repeated and the same sentence - "this host has no
 * Docker socket" - written once per host. That is grouping by host wearing
 * the clothes of grouping by cause, so the reason is said once when every
 * host gave the same one and per host only when they differ.
 */
function Gaps({ gaps, opened, onOpen, testId }: {
  gaps: ReadinessGap[];
  opened: string;
  onOpen: (requirement: string) => void;
  testId: string;
}) {
  const t = useT();
  return (
    <Table
      rows={gaps}
      keyOf={(one) => one.requirement}
      rowTestId={(one) => `gap-${one.requirement}`}
      testId={testId}
      columns={[
        {
          key: "requirement",
          head: t("What is missing"),
          tight: true,
          cell: (one) => <code title={one.requirement}>{one.requirement}</code>,
        },
        {
          key: "blocks",
          head: t("Work it blocks"),
          cell: (one) => (
            <button
              type="button"
              className="fl-word"
              aria-pressed={opened === one.requirement}
              onClick={() => onOpen(opened === one.requirement ? "" : one.requirement)}
            >
              {/* "1 operations" is how a screen tells you nobody read it. */}
              {one.operations.length === 1
                ? t("{n} operation", { n: 1 })
                : t("{n} operations", { n: one.operations.length })}
            </button>
          ),
        },
        {
          key: "hosts",
          head: t("On"),
          cell: (one) => (
            <Stack>
              <Tags>
                {one.hosts.map((host) => (
                  <Tag key={host.id}><Link to={`/hosts/${host.id}`}>{host.hostname}</Link></Tag>
                ))}
              </Tags>
              {one.satisfied > 0 && (
                <span className="fl-faint">
                  {one.satisfied === 1
                    ? t("{n} host offers it", { n: 1 })
                    : t("{n} hosts offer it", { n: one.satisfied })}
                </span>
              )}
            </Stack>
          ),
        },
        { key: "said", head: t("What the host said"), cell: (one) => <Said gap={one} /> },
      ]}
    />
  );
}

/**
 * The agent's own sentence, which is the remedy as well as the diagnosis:
 * "this host has no Docker Compose plugin" says what to install.
 *
 * A host that reported no adapter registry said nothing at all, and that
 * is drawn as unknown rather than as a missing adapter - it is the one
 * distinction this screen was written to keep.
 */
function Said({ gap }: { gap: ReadinessGap }) {
  const t = useT();
  const silent = gap.hosts.filter((host) => host.silent).length;
  const reasons = new Set(gap.hosts.map((host) => (host.silent ? "" : host.reason || "")));
  const shared = reasons.size === 1 ? [...reasons][0] : "";

  if (silent > 0 && silent === gap.hosts.length) {
    return <Pill tone="unknown">{t("has reported no adapter at all")}</Pill>;
  }
  if (shared) return <>{shared}</>;
  return (
    <Stack>
      {gap.hosts.map((host) => (
        <TwoLine
          key={host.id}
          sub={host.silent
            ? <Pill tone="unknown">{t("has reported no adapter at all")}</Pill>
            : host.reason || <Pill tone="unknown">{t("gave no reason")}</Pill>}
        >
          {host.hostname}
        </TwoLine>
      ))}
    </Stack>
  );
}

export const READINESS_SCREEN = "next_readiness";

export const READINESS: BoardEntry[] = [
  { key: "hosts", title: "Hosts", width: 3, height: 1 },
  { key: "silent", title: "Silent about their adapters", width: 3, height: 1 },
  { key: "operations", title: "Operations that need an adapter", width: 3, height: 1 },
  { key: "unorderable", title: "Orderable nowhere", width: 3, height: 1 },
  { key: "nowhere", title: "Nowhere in this fleet", width: 12, height: 3 },
  { key: "somewhere", title: "On some hosts", width: 12, height: 3 },
  { key: "blocked", title: "What it blocks", width: 12, height: 2 },
];
