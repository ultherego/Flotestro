import { useEffect, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { awaitJob, type JobAttempt } from "../../../lib/jobs";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { unitOrder, unitToggleOrder } from "../../../lib/host/services";
import { useModuleRefresh } from "../../../lib/host/module";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Bars, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Find, HeadActions,
  Modal, Note, PAGE_SIZES, Pager, Pill, Problem, Readout, Table, Tag, Tags, Toolbar, type Segment, type Tone,
} from "../../kit";

/**
 * The systemd units of one host: what failed, what runs, and what starts
 * at boot.
 *
 * The screen is built around one distinction. An unread host and a host
 * with nothing wrong look the same in a count of none, and they are not
 * the same answer - so every figure here is an em dash until the host has
 * actually been read, and the failed units come from the inventory, which
 * knows them earlier than the full listing does.
 */

type ServicesState = {
  failed_units: string[] | null;
  failed_units_known: boolean;
};

export type Unit = {
  name: string;
  load_state: string;
  active_state: string;
  sub_state: string;
  unit_file_state?: string;
  result?: string;
  main_pid?: number;
  n_restarts?: number;
};

type UnitListing = { units?: Unit[]; truncated?: boolean };

type UnitDropIn = { path: string; content?: string; truncated?: boolean; error?: string };

/** The full picture of one unit, as the host prints it for a detail read. */
export type UnitDetail = {
  state: Unit;
  description?: string;
  fragment_path?: string;
  requires?: string[];
  wants?: string[];
  after?: string[];
  before?: string[];
  binds_to?: string[];
  part_of?: string[];
  triggered_by?: string[];
  triggers?: string[];
  drop_ins?: UnitDropIn[];
  exec_main_start?: string;
  journal_lines?: string[];
  journal_cursor?: string;
  journal_truncated?: boolean;
  journal_error?: string;
};

type DetailDocument = { kind?: string; units?: UnitDetail[] };

/** The detail of a read, typed by the panel from the result of the agent. */
export function detailDocumentOf(attempt: JobAttempt<DetailDocument>): DetailDocument {
  const detail = attempt.detail;
  if (detail?.kind === "unit_detail") return detail;
  try {
    return JSON.parse(attempt.stdout ?? "{}") as DetailDocument;
  } catch {
    return {};
  }
}

/** The changes this screen offers; when every one is refused, it says so once. */
export const UNIT_CHANGES = [
  "unit.restart", "unit.start", "unit.stop", "unit.reset_failed", "unit.enable.set", "unit.mask.set",
];

/** How a unit's active state reads as a condition. */
export function unitTone(state: string): Tone {
  if (state === "active") return "ok";
  if (state === "failed") return "error";
  if (state === "inactive") return "neutral";
  return "unknown";
}

/** A count of what satisfies a test, or nothing at all when the list is unread. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/**
 * A control that exists only where the order it places would be taken.
 *
 * A refused order is not the way to learn about a missing permission, so
 * the button is not drawn at all; where the action is the point of the
 * card, `explain` leaves the server's reason in its place.
 */
function Guard({ action, host, explain, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

export function Services({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();

  const module = useQuery({
    queryKey: ["inventory", host.id, "services"],
    queryFn: () => api.get<InventoryFragment<ServicesState>>(`/api/v1/hosts/${host.id}/inventory/services`),
    retry: false,
  });
  const listing = useQuery({
    queryKey: ["inventory", host.id, "services.full"],
    queryFn: () => api.get<InventoryFragment<UnitListing>>(`/api/v1/hosts/${host.id}/inventory/services.full`),
    retry: false,
  });
  // The full listing lands in the inventory when the read is over; the
  // other operations change what the next inventory cycle reports.
  const refresh = useModuleRefresh(host.id, ["services", "services.full"]);

  const [filter, setFilter] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [toMask, setToMask] = useState<Unit | null>(null);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, UnitDetail>>({});
  const [detailError, setDetailError] = useState("");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);

  const failed = module.data?.payload?.failed_units ?? [];
  const known = module.data?.payload?.failed_units_known ?? false;

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setProblem("");
      setNotice(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      setToMask(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refresh(job);
    },
    onError: (error) => setProblem(error instanceof Error ? error.message : String(error)),
  });

  // The detail of one unit is a read the screen waits for: the host answers
  // with a document rather than with a state that lands in the inventory,
  // because the detail of one unit is not a listing of the host.
  const detail = useMutation({
    mutationFn: async (unit: string) => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "unit.status",
        payload: { unit_status: { units: [unit], detail: true } },
      });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      const last = await awaitJob<DetailDocument>(api, job.id);
      if (!last) throw new Error(t("The host did not answer in time."));
      if (last.status !== "succeeded") {
        throw new Error(last.message || last.error_code || t("The host refused the read."));
      }
      const document = detailDocumentOf(last);
      const found = document.units?.find((entry) => entry.state?.name === unit) ?? document.units?.[0];
      if (!found) throw new Error(t("The host returned no detail for {unit}.", { unit }));
      return found;
    },
    onSuccess: (found, unit) => {
      setDetailError("");
      setDetails((previous) => ({ ...previous, [unit]: found }));
    },
    onError: (error) => setDetailError(error instanceof Error ? error.message : String(error)),
  });

  function operation(action: string, unit: string) {
    const order = unitOrder(action, unit);
    if (order.problems.length > 0) {
      setProblem(t(order.problems[0].message, order.problems[0].params));
      return;
    }
    setProblem("");
    request.mutate({ action, payload: order.payload });
  }

  function toggle(action: string, unit: string, value: boolean) {
    const order = unitToggleOrder(action, unit, value);
    if (order.problems.length > 0) {
      setProblem(t(order.problems[0].message, order.problems[0].params));
      return;
    }
    setProblem("");
    request.mutate({
      action,
      ...(action === "unit.mask.set" ? { reason: "unit masking from the panel" } : {}),
      payload: order.payload,
    });
  }

  function open(unit: string, again = false) {
    setExpanded(unit);
    setDetailError("");
    if (again || !details[unit]) detail.mutate(unit);
  }

  // A dependency leads to its unit through the address, so the link can be
  // taken, shared and walked back.
  const wanted = params.get("unit") ?? "";
  useEffect(() => {
    if (!wanted) return;
    setFilter(wanted);
    setActiveOnly(false);
    setPage(1);
    open(wanted);
    // The unit in the address is what the effect answers to; the rest is
    // read at that moment.
  }, [wanted]); // eslint-disable-line react-hooks/exhaustive-deps

  const lead = (unit: string) => {
    const next = new URLSearchParams(params);
    next.set("unit", unit);
    setParams(next);
  };

  const allUnits = listing.data?.payload?.units ?? [];
  const units = allUnits.filter((unit) => {
    if (activeOnly && unit.active_state !== "active") return false;
    if (!filter) return true;
    return unit.name.toLowerCase().includes(filter.toLowerCase());
  });
  const shown = units.slice((page - 1) * size, page * size);
  // The unit opened from the address is always on the page, wherever the
  // alphabet put it: the operator followed a link to it.
  if (expanded && !shown.some((unit) => unit.name === expanded)) {
    const opened = units.find((unit) => unit.name === expanded);
    if (opened) shown.push(opened);
  }

  // The state counts come from the full listing, which exists only after a
  // read; the failed count comes from the inventory and is known earlier.
  const listed = listing.data ? allUnits : undefined;
  const failedCount = known ? failed.length : countWhere(listed, (unit) => unit.active_state === "failed");
  const bootStates = ["enabled", "disabled", "static", "masked"];

  const states: Segment[] = [
    { label: t("active"), value: countWhere(listed, (unit) => unit.active_state === "active"), tone: "ok" },
    { label: t("failed"), value: failedCount, tone: "error" },
    { label: t("inactive"), value: countWhere(listed, (unit) => unit.active_state === "inactive"), tone: "neutral" },
    {
      label: t("other"),
      value: countWhere(listed, (unit) => !["active", "failed", "inactive"].includes(unit.active_state)),
      tone: "unknown",
    },
  ];

  const opened = expanded ? units.find((one) => one.name === expanded) : undefined;
  const freshness = module.data
    ? t("Source: {source}, revision {revision}, observed {when}", {
        source: module.data.source,
        revision: module.data.revision.slice(0, 12),
        when: relativeTime(module.data.observed_at),
      })
    : undefined;

  return (
    <>
      <HeadActions>
        <Guard action="unit.status" host={host.id} explain>
          <Button
            onClick={() => request.mutate({ action: "unit.status", payload: { unit_status: { all: true } } })}
            disabled={request.isPending || host.connection_state !== "online"}
            testId="read-units"
          >
            {request.isPending ? t("Requesting…") : t("Read from host")}
          </Button>
        </Guard>
      </HeadActions>

      <ReadOnlyNotice host={host.id} actions={UNIT_CHANGES} />
      {module.data?.unavailable_reason && (
        <Banner tone="warn">
          {t("The units could not be read: {reason}", { reason: module.data.unavailable_reason })}
        </Banner>
      )}
      {/* A cut-off listing is marked: a list without that mark reads as the
          whole of the host. */}
      {listing.data?.payload?.truncated && (
        <Banner tone="warn">{t("The list was truncated by the host limit; narrow the filter on the host.")}</Banner>
      )}
      {notice && <Banner tone="info">{notice}</Banner>}
      {problem && <Problem>{problem}</Problem>}

      {toMask && (
        <MaskUnit
          host={host}
          unit={toMask}
          busy={request.isPending}
          onCancel={() => setToMask(null)}
          onConfirm={(reason) => request.mutate({
            action: "unit.mask.set",
            reason,
            payload: unitToggleOrder("unit.mask.set", toMask.name, true).payload,
          })}
        />
      )}

      <Board screen={HOST_SERVICES_SCREEN} catalogue={HOST_SERVICES} drawn={{
        states: (
          <Card
            title={t("Unit states")}
            note={t("Every unit the host lists, by its active state.")}
            foot={freshness}
          >
            <Band segments={states} testId="unit-states" />
          </Card>
        ),

        failed: (
          <Card
            title={t("Failed units")}
            note={t("The reason to open this screen: what the host could not keep running.")}
            flush
          >
            {!known
              ? <Empty icon="help">{t("Unit states could not be determined.")}</Empty>
              : failed.length === 0
                ? <Empty>{t("No unit is in a failed state.")}</Empty>
                : (
                  <Table
                    rows={failed}
                    keyOf={(one) => one}
                    testId="failed-units"
                    rowTestId={(one) => `failed-${one}`}
                    columns={[
                      {
                        key: "unit", head: t("Unit"), tight: true,
                        cell: (one) => <Button kind="word" onClick={() => lead(one)}>{one}</Button>,
                      },
                      {
                        key: "actions", head: t("Actions"), actions: true, optional: true, cell: (one) => (
                          <>
                            <Guard action="unit.restart" host={host.id}>
                              <Button onClick={() => operation("unit.restart", one)}>{t("Restart")}</Button>
                            </Guard>
                            <Guard action="unit.start" host={host.id}>
                              <Button kind="quiet" onClick={() => operation("unit.start", one)}>{t("Start")}</Button>
                            </Guard>
                            {/* Clearing the record after a fix: the next
                                failure is then told from the one seen. */}
                            <Guard action="unit.reset_failed" host={host.id}>
                              <Button kind="quiet" onClick={() => operation("unit.reset_failed", one)}>
                                {t("Reset failed")}
                              </Button>
                            </Guard>
                          </>
                        ),
                      },
                    ]}
                  />
                )}
          </Card>
        ),

        onboot: (
          <Card
            title={t("On boot")}
            note={t("What the unit files say happens at boot: enabled starts, disabled waits for a hand, static is pulled in by another unit, masked cannot start at all.")}
          >
            {listed
              ? (
                <Bars items={[
                  ...bootStates.map((state) => ({
                    label: state,
                    value: countWhere(listed, (unit) => unit.unit_file_state === state) ?? 0,
                    tone: (state === "masked" ? "warn" : state === "enabled" ? "ok" : "info") as Tone,
                  })),
                  {
                    label: t("other"),
                    value: countWhere(listed, (unit) => !bootStates.includes(unit.unit_file_state ?? "")) ?? 0,
                    tone: "info" as Tone,
                  },
                ]} />
              )
              : <Empty icon="help">{t("Known after a read from the host.")}</Empty>}
          </Card>
        ),

        units: (
          <Card
            title={t("All units")}
            note={t("The full list is read from the host on request, not on every inventory cycle.")}
            flush
          >
            <Toolbar
              end={listing.data
                ? (
                  <Pager
                    page={page}
                    size={size}
                    total={units.length}
                    onPage={setPage}
                    onSize={setSize}
                    sizes={PAGE_SIZES}
                  />
                )
                : undefined}
            >
              <Find
                value={filter}
                onChange={(value) => { setFilter(value); setPage(1); }}
                placeholder={t("Filter by name")}
                testId="unit-filter"
              />
              <Check checked={activeOnly} onChange={(value) => { setActiveOnly(value); setPage(1); }}>
                {t("active only")}
              </Check>
            </Toolbar>
            {!listing.data
              ? <Empty icon="services">{t("This host has not been read yet. Use “Read from host”.")}</Empty>
              : (
                <Table
                  rows={shown}
                  keyOf={(one) => one.name}
                  rowTestId={(one) => `unit-${one.name}`}
                  testId="units"
                  empty={t("No unit answers this filter.")}
                  /* The unit's detail belongs under its own row: the panel
                     being replaced put it in a second row there, and a card
                     elsewhere on the board makes the reader hunt for it. */
                  opened={(one) => one.name === expanded}
                  detail={(one) => (
                    <UnitDetailCard
                      hostID={host.id}
                      unit={one}
                      detail={details[one.name]}
                      loading={detail.isPending && detail.variables === one.name}
                      error={detailError}
                      onLead={lead}
                      onRetry={() => open(one.name, true)}
                    />
                  )}
                  /* The columns an operator folds away are this browser's,
                     and the unit's name and its buttons always stay. */
                  remember="fl.columns.host-services"
                  columns={[
                    {
                      key: "unit", head: t("Unit"), tight: true, cell: (one) => (
                        <Button
                          kind="word"
                          onClick={() => (expanded === one.name ? setExpanded(null) : open(one.name))}
                          title={expanded === one.name ? t("Hide the detail") : t("Show the detail")}
                        >
                          {one.name}
                        </Button>
                      ),
                    },
                    {
                      key: "active", head: t("Active"), optional: true,
                      cell: (one) => <Pill tone={unitTone(one.active_state)}>{one.active_state}</Pill>,
                    },
                    { key: "sub", head: t("Sub-state"), minor: true, optional: true, cell: (one) => one.sub_state || "—" },
                    { key: "onboot", head: t("On boot"), optional: true, cell: (one) => one.unit_file_state || "—" },
                    {
                      key: "actions", head: t("Actions"), actions: true, optional: true, cell: (one) => (
                        <>
                          {one.active_state === "active" ? (
                            <>
                              <Guard action="unit.restart" host={host.id}>
                                <Button kind="quiet" onClick={() => operation("unit.restart", one.name)}>{t("Restart")}</Button>
                              </Guard>
                              <Guard action="unit.stop" host={host.id}>
                                <Button kind="quiet" onClick={() => operation("unit.stop", one.name)}>{t("Stop")}</Button>
                              </Guard>
                            </>
                          ) : (
                            <Guard action="unit.start" host={host.id}>
                              <Button kind="quiet" onClick={() => operation("unit.start", one.name)}>{t("Start")}</Button>
                            </Guard>
                          )}
                          {one.active_state === "failed" && (
                            <Guard action="unit.reset_failed" host={host.id}>
                              <Button kind="quiet" onClick={() => operation("unit.reset_failed", one.name)}>
                                {t("Reset failed")}
                              </Button>
                            </Guard>
                          )}
                          {/* Enabling changes what the host does after a
                              reboot, so it is separate from starting now. */}
                          <Guard action="unit.enable.set" host={host.id}>
                            {one.unit_file_state === "enabled" ? (
                              <Button kind="quiet" onClick={() => toggle("unit.enable.set", one.name, false)}>{t("Disable")}</Button>
                            ) : one.unit_file_state === "disabled" ? (
                              <Button kind="quiet" onClick={() => toggle("unit.enable.set", one.name, true)}>{t("Enable")}</Button>
                            ) : <></>}
                          </Guard>
                          <Guard action="unit.mask.set" host={host.id}>
                            {one.unit_file_state === "masked" ? (
                              <Button kind="quiet" onClick={() => toggle("unit.mask.set", one.name, false)}>{t("Unmask")}</Button>
                            ) : (
                              <Button kind="danger" onClick={() => setToMask(one)} testId={`mask-${one.name}`}>{t("Mask")}</Button>
                            )}
                          </Guard>
                        </>
                      ),
                    },
                  ]}
                />
              )}
          </Card>
        ),

        /* A unit with a row shows its detail under that row. This container
           is for the one that has none: a failed unit opened before the
           listing was read, or one the filter leaves out. The detail is its
           own read, not a row of the list. */
        detail: expanded !== null && !shown.some((one) => one.name === expanded) && (
          <Card
            title={expanded}
            note={t("What the host says about this unit, read on its own.")}
          >
            <UnitDetailCard
              hostID={host.id}
              unit={opened ?? { name: expanded, load_state: "", active_state: "", sub_state: "" }}
              detail={details[expanded]}
              loading={detail.isPending && detail.variables === expanded}
              error={detailError}
              onLead={lead}
              onRetry={() => open(expanded, true)}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * The detail of one unit: the facts, the dependencies, the overrides and
 * the last journal lines.
 */
function UnitDetailCard({ hostID, unit, detail, loading, error, onLead, onRetry }: {
  hostID: string;
  unit: Unit;
  detail?: UnitDetail;
  loading: boolean;
  error: string;
  onLead: (unit: string) => void;
  onRetry: () => void;
}) {
  const t = useT();
  if (error) {
    return (
      <>
        <Problem>{error}</Problem>
        <Actions><Button kind="quiet" onClick={onRetry}>{t("Read again")}</Button></Actions>
      </>
    );
  }
  if (!detail) {
    return loading
      ? <Empty icon="services">{t("The host is being asked about this unit.")}</Empty>
      : <Empty icon="services">{t("The detail has not been read yet.")}</Empty>;
  }

  const state = detail.state;
  const dependencies = [
    { label: t("Requires"), units: detail.requires },
    { label: t("Wants"), units: detail.wants },
    { label: t("Bound to"), units: detail.binds_to },
    { label: t("Part of"), units: detail.part_of },
    { label: t("After"), units: detail.after },
    { label: t("Before"), units: detail.before },
  ].filter((group) => group.units && group.units.length > 0);
  const activation = [
    { label: t("Triggered by"), units: detail.triggered_by },
    { label: t("Triggers"), units: detail.triggers },
  ].filter((group) => group.units && group.units.length > 0);
  const lines = detail.journal_lines ?? [];
  const logs = `/hosts/${hostID}/logs?unit=${encodeURIComponent(unit.name)}${
    detail.journal_cursor ? `&cursor=${encodeURIComponent(detail.journal_cursor)}` : ""}`;

  return (
    <div data-testid="unit-detail">
      <Facts>
        <Fact label={t("Description")}>{detail.description || "—"}</Fact>
        <Fact label={t("Unit file")}>{detail.fragment_path || "—"}</Fact>
        <Fact label={t("State")}>
          <Pill tone={unitTone(state.active_state)}>{state.active_state || "—"}</Pill>
          {state.sub_state ? ` ${state.sub_state}` : ""}
          {state.result && state.result !== "success" && <Pill tone="warn">{state.result}</Pill>}
        </Fact>
        <Fact label={t("Main PID")}>{state.main_pid || "—"}</Fact>
        {/* A restart count above zero is the mark of a unit that keeps
            falling over; "active" alone would hide it. */}
        <Fact label={t("Restarts")}>
          {(state.n_restarts ?? 0) > 0
            ? <Pill tone="warn">{state.n_restarts}</Pill>
            : state.n_restarts ?? "—"}
        </Fact>
        <Fact label={t("Main process started")}>
          {detail.exec_main_start
            ? <span title={absoluteTime(detail.exec_main_start)}>{relativeTime(detail.exec_main_start)}</span>
            : "—"}
        </Fact>
        <Fact label={t("On boot")}>{state.unit_file_state || "—"}</Fact>
      </Facts>

      {/* Every dependency leads to its unit: the list narrows to it and its
          own detail opens. */}
      {dependencies.map((group) => (
        <Facts key={group.label}>
          <Fact label={group.label}>
            <Tags>
              {(group.units ?? []).map((name) => (
                <Tag key={name} to={`/hosts/${hostID}/services?unit=${encodeURIComponent(name)}`}>{name}</Tag>
              ))}
            </Tags>
          </Fact>
        </Facts>
      ))}
      {activation.map((group) => (
        <Facts key={group.label}>
          <Fact label={group.label}>
            <Tags>
              {(group.units ?? []).map((name) => (
                <Tag key={name} to={`/hosts/${hostID}/services?unit=${encodeURIComponent(name)}`}>{name}</Tag>
              ))}
            </Tags>
          </Fact>
        </Facts>
      ))}

      {!detail.drop_ins?.length
        ? <Note>{t("No override files.")}</Note>
        : (detail.drop_ins ?? []).map((dropIn) => (
          dropIn.error
            ? <Note key={dropIn.path}>{t("{path}: not read — {reason}", { path: dropIn.path, reason: dropIn.error })}</Note>
            : (
              <Readout
                key={dropIn.path}
                label={dropIn.path}
                value={`${dropIn.content ?? ""}${dropIn.truncated ? `\n… ${t("truncated")}` : ""}`}
                lines={8}
              />
            )
        ))}

      {detail.journal_error
        ? <Banner tone="warn">{detail.journal_error}</Banner>
        : lines.length === 0
          ? <Note>{t("The journal has nothing for this unit.")}</Note>
          : (
            <Readout
              label={t("Last journal lines")}
              value={lines.join("\n")}
              lines={12}
              note={detail.journal_truncated ? t("output truncated") : undefined}
              testId="unit-journal"
            />
          )}

      <Actions>
        {/* The Logs screen continues right after the last line shown here:
            the cursor travels in the address. */}
        <Tag to={logs}>{t("Follow in Logs")}</Tag>
        <Button kind="quiet" onClick={() => onLead(unit.name)}>{t("Narrow the list to this unit")}</Button>
        <Button kind="quiet" onClick={onRetry}>{t("Read again")}</Button>
      </Actions>
    </div>
  );
}

/** How long a reason has to be before the trail will take it. */
export const REASON_MIN_LENGTH = 8;

/**
 * Masking a unit cannot be undone by starting it again, and it survives a
 * reboot: it is asked for by name, with a reason, before anything is sent.
 */
function MaskUnit({ host, unit, busy, onConfirm, onCancel }: {
  host: Host;
  unit: Unit;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= REASON_MIN_LENGTH && confirmation === host.hostname;

  return (
    <Modal
      title={t("Mask unit")}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button kind="danger" disabled={!ready || busy} onClick={() => onConfirm(reason.trim())} testId="mask-confirm">
            {busy ? t("Requesting…") : t("Mask unit")}
          </Button>
        </>
      }
    >
      <Note>
        {t("{unit} will not be startable, by the panel or by hand, and the change survives a reboot.", { unit: unit.name })}
      </Note>
      {/* The target repeated at the button: the operator approves a
          specific machine, not "the host I think I have open". */}
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="mask-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            data-testid="mask-hostname"
          />
        </Field>
      </Fields>
    </Modal>
  );
}

/** The name this screen's arrangement is stored under. */
export const HOST_SERVICES_SCREEN = "next_host_services";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_SERVICES: BoardEntry[] = [
  { key: "states", title: "Unit states", width: 12, height: 2 },
  { key: "failed", title: "Failed units", width: 6, height: 3 },
  // The four unit-file states and "other": five bars on every host.
  { key: "onboot", title: "On boot", width: 6, height: 2 },
  { key: "units", title: "All units", width: 12, height: 5 },
  { key: "detail", title: "The unit", width: 12, height: 5 },
];
