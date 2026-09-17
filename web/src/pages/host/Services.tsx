import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../../lib/api";
import { awaitJob, type JobAttempt } from "../../lib/jobs";
import type { Job } from "../../lib/types";
import { absoluteTime } from "../../lib/format";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { ColumnChooser, Td, Th, useColumns, type ColumnDef, type Columns } from "../../components/SortableTable";
import {
  Fact, Facts, Foot, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere,
  useHost, useModule, useModuleRefresh,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type ServicesState = {
  failed_units: string[] | null;
  failed_units_known: boolean;
};

type Unit = {
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
type UnitDetail = {
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

type Attempt = JobAttempt<DetailDocument>;

/** How many units the list shows before the operator asks for more. */
const UNIT_PAGE = 50;

/**
 * The detail of a read, typed by the panel from the result of the agent. An
 * agent from before the typed result prints the same document on stdout, so
 * stdout stays the fallback for one release; drop it together with the
 * support for those agents.
 */
function detailDocumentOf(attempt: Attempt): DetailDocument {
  const detail = attempt.detail;
  if (detail?.kind === "unit_detail") return detail;
  return JSON.parse(attempt.stdout ?? "{}") as DetailDocument;
}

/** The columns of the unit list; the unit name cannot be taken off the screen. */
export function unitColumns(t: (text: string) => string): ColumnDef[] {
  return [
    { key: "unit", label: t("Unit"), fixed: true },
    { key: "active", label: t("Active") },
    { key: "sub_state", label: t("Sub-state"), secondary: true },
    { key: "on_boot", label: t("On boot") },
    { key: "actions", label: t("Actions") },
  ];
}

export function Services() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<ServicesState>(host.id, "services");
  const listing = useModule<UnitListing>(host.id, "services.full");
  // The full listing lands in the inventory when the read is over; the
  // other operations change what the next inventory cycle reports.
  const refresh = useModuleRefresh(host.id, ["services", "services.full"]);
  const [params] = useSearchParams();
  const [filter, setFilter] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [toMask, setToMask] = useState<Unit | null>(null);
  const [message, setMessage] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  // The list grows a page at a time: two hundred rows at once make the
  // page a scroll of nothing, and the filter is the way to a unit anyway.
  const [limit, setLimit] = useState(UNIT_PAGE);
  const [details, setDetails] = useState<Record<string, UnitDetail>>({});
  const [detailError, setDetailError] = useState("");
  // The columns of the unit list, remembered per table in the browser.
  // The unit name is the identity of a row and stays on the screen.
  const columns = useColumns("host-services", unitColumns(t));

  const failed = module.data?.payload?.failed_units ?? [];
  const known = module.data?.payload?.failed_units_known ?? false;

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setToMask(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refresh(job);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
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
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
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
    request.mutate({ action, payload: { unit: { unit } } });
  }

  function toggle(action: string, unit: string, value: boolean) {
    request.mutate({
      action,
      ...(action === "unit.mask.set" ? { reason: "unit masking from the panel" } : {}),
      payload: { unit_toggle: { unit, enabled: value } },
    });
  }

  function open(unit: string, refresh = false) {
    setExpanded(unit);
    setDetailError("");
    if (refresh || !details[unit]) detail.mutate(unit);
  }

  // A dependency chip links to its unit with ?unit=: the list narrows to it
  // and its own detail opens, so the operator walks the graph link by link
  // and the browser history walks back.
  const wanted = params.get("unit") ?? "";
  useEffect(() => {
    if (!wanted) return;
    setFilter(wanted);
    setActiveOnly(false);
    open(wanted);
    // The unit in the address is what the effect answers to; the rest is
    // read at that moment.
  }, [wanted]); // eslint-disable-line react-hooks/exhaustive-deps

  const allUnits = listing.data?.payload?.units ?? [];
  const units = allUnits.filter((unit) => {
    if (activeOnly && unit.active_state !== "active") return false;
    if (!filter) return true;
    return unit.name.toLowerCase().includes(filter.toLowerCase());
  });
  // The unit opened from the address is always on the page, wherever the
  // alphabet put it: the operator followed a link to it.
  const page = units.slice(0, limit);
  if (expanded && !page.some((unit) => unit.name === expanded)) {
    const opened = units.find((unit) => unit.name === expanded);
    if (opened) page.push(opened);
  }
  // The state counts come from the full listing, which exists only after a
  // read; the failed count comes from the inventory and is known earlier.
  // Neither is zero before it is known.
  const listed = listing.data ? allUnits : undefined;
  const failedCount = known ? failed.length : countWhere(listed, (unit) => unit.active_state === "failed");
  const bootStates = ["enabled", "disabled", "static", "masked"];

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Services")}
        description={t("systemd units: what failed, what runs and what starts at boot.")}
        actions={
          <button
            onClick={() => request.mutate({ action: "unit.status", payload: { unit_status: { all: true } } })}
            disabled={request.isPending || host.connection_state !== "online"}
          >
            {request.isPending ? t("Requesting…") : t("Read from host")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      <Widgets>
      {/* An unread state must not look like no failed units: the bar shows
          dashes until the host has been read. */}
      <Summary
        title={t("Unit states")}
        description={t("Every unit the host lists, by its active state.")}
        span={12}
        segments={[
          { label: t("active"), value: countWhere(listed, (unit) => unit.active_state === "active"), tone: "ok" },
          { label: t("failed"), value: failedCount, tone: "error" },
          { label: t("inactive"), value: countWhere(listed, (unit) => unit.active_state === "inactive"), tone: "neutral" },
          { label: t("other"), value: countWhere(listed, (unit) => !["active", "failed", "inactive"].includes(unit.active_state)), tone: "unknown" },
        ]}
      />

      {/* The failed units stand first: they are the reason to open the
          page. Beside them, what starts at boot; the full list runs under
          both across the width, so an empty failed list never stretches
          beside two hundred rows. */}
      <Section title={t("Failed units")} count={known ? failed.length : undefined} span={6} flush>
        {!known ? (
          <Empty>{t("Unit states could not be determined.")}</Empty>
        ) : failed.length === 0 ? (
          <Empty>{t("No unit is in a failed state.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Unit")}</th><th>{t("Actions")}</th></tr></thead>
            <tbody>
              {failed.map((unit) => (
                <tr key={unit}>
                  <td className="hm-mono">
                    <Link to={`?unit=${encodeURIComponent(unit)}`}>{unit}</Link>
                  </td>
                  <td>
                    <div className="operations">
                      <button onClick={() => operation("unit.restart", unit)}>{t("Restart")}</button>
                      <button onClick={() => operation("unit.start", unit)}>{t("Start")}</button>
                      {/* Clearing the record after a fix: the next failure
                          is then told from the one already seen. */}
                      <button className="secondary" onClick={() => operation("unit.reset_failed", unit)}>{t("Reset failed")}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title={t("On boot")} span={6} description={t("What the unit files say happens at boot: enabled starts, disabled waits for a hand, static is pulled in by another unit, masked cannot start at all.")}>
        {listed ? (
          <Breakdown
            items={[
              ...bootStates.map((state) => ({
                label: state, value: countWhere(listed, (unit) => unit.unit_file_state === state) ?? 0,
                tone: state === "masked" ? "warn" as const : state === "enabled" ? "ok" as const : "info" as const,
              })),
              { label: t("other"), value: countWhere(listed, (unit) => !bootStates.includes(unit.unit_file_state ?? "")) ?? 0, tone: "info" as const },
            ]}
          />
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("Known after a read from the host.")}</p>
        )}
      </Section>

      <Section
        title={t("All units")}
        count={listing.data ? units.length : undefined}
        span={12}
        description={t("The full list is read from the host on request, not on every inventory cycle.")}
        tools={listing.data && (
          <>
            <input
              placeholder={t("Filter by name")}
              value={filter}
              onChange={(e) => { setFilter(e.target.value); setLimit(UNIT_PAGE); }}
            />
            <label className="toggle">
              <input
                type="checkbox"
                checked={activeOnly}
                onChange={(e) => setActiveOnly(e.target.checked)}
              />
              {t("active only")}
            </label>
            <ColumnChooser columns={columns} />
          </>
        )}
        flush
      >
        {!listing.data ? (
          <>
            <Empty>{t("This host has not been read yet. Use “Read from host”.")}</Empty>
            {/* A failed unit opened before the listing was read still gets
                its detail: the detail is its own read, not a row of the
                list. */}
            {expanded && (
              <div className="hm-section-body">
                <p className="widget-subhead hm-mono">{expanded}</p>
                <UnitDetailPanel
                  unit={{ name: expanded, load_state: "", active_state: "", sub_state: "" }}
                  detail={details[expanded]}
                  loading={detail.isPending && detail.variables === expanded}
                  error={detailError}
                  onRefresh={() => open(expanded, true)}
                />
              </div>
            )}
          </>
        ) : (
          <>
            {/* A cut-off listing is marked: a list without that mark would
                look complete. */}
            {listing.data.payload?.truncated && (
              <p className="warning">
                <span>{t("The list was truncated by the host limit; narrow the filter on the host.")}</span>
              </p>
            )}
            <Table>
              <thead>
                <tr>
                  {columns.all.map((column) => <Th key={column.key} columns={columns} name={column.key} />)}
                </tr>
              </thead>
              <tbody>
                {page.map((unit) => (
                  <UnitRow
                    key={unit.name}
                    columns={columns}
                    unit={unit}
                    expanded={expanded === unit.name}
                    detail={details[unit.name]}
                    loading={detail.isPending && detail.variables === unit.name}
                    error={expanded === unit.name ? detailError : ""}
                    onToggle={() => (expanded === unit.name ? setExpanded(null) : open(unit.name))}
                    onRefresh={() => open(unit.name, true)}
                    onOperation={operation}
                    onEnable={(value) => toggle("unit.enable.set", unit.name, value)}
                    onUnmask={() => toggle("unit.mask.set", unit.name, false)}
                    onMask={() => setToMask(unit)}
                  />
                ))}
              </tbody>
            </Table>
            <Foot>
              <span>
                {t("{shown} of {total} units shown · read", { shown: page.length, total: allUnits.length })}{" "}
                <Time value={listing.data.observed_at} />
              </span>
              {units.length > page.length && (
                <button className="secondary" onClick={() => setLimit((current) => current + UNIT_PAGE)}>
                  {t("Show {n} more", { n: Math.min(UNIT_PAGE, units.length - page.length) })}
                </button>
              )}
            </Foot>
          </>
        )}
      </Section>
      </Widgets>

      {toMask && (
        <TargetConfirmation
          host={host}
          label={t("Mask unit")}
          description={t("{unit} will not be startable, by the panel or by hand, and the change survives a reboot.", { unit: toMask.name })}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              action: "unit.mask.set",
              reason,
              payload: { unit_toggle: { unit: toMask.name, enabled: true } },
            })
          }
          onCancel={() => setToMask(null)}
        />
      )}
    </ModulePage>
  );
}

/** One unit of the list, with its detail panel under it when opened. */
function UnitRow({
  columns, unit, expanded, detail, loading, error, onToggle, onRefresh, onOperation, onEnable, onUnmask, onMask,
}: {
  columns: Columns;
  unit: Unit;
  expanded: boolean;
  detail?: UnitDetail;
  loading: boolean;
  error: string;
  onToggle: () => void;
  onRefresh: () => void;
  onOperation: (action: string, unit: string) => void;
  onEnable: (value: boolean) => void;
  onUnmask: () => void;
  onMask: () => void;
}) {
  const t = useT();
  return (
    <>
      <tr>
        <Td columns={columns} name="unit" className="hm-mono">
          <button
            type="button"
            className="secondary"
            onClick={onToggle}
            aria-expanded={expanded}
            title={expanded ? t("Hide the detail") : t("Show the detail")}
          >
            {expanded ? "▾" : "▸"}
          </button>{" "}
          {unit.name}
        </Td>
        <Td columns={columns} name="active">
          <span className={unit.active_state === "active" ? "badge ok" : unit.active_state === "failed" ? "badge error" : "badge"}>
            {unit.active_state}
          </span>
        </Td>
        <Td columns={columns} name="sub_state">{unit.sub_state}</Td>
        <Td columns={columns} name="on_boot">{unit.unit_file_state || "—"}</Td>
        <Td columns={columns} name="actions">
          <div className="operations">
            {unit.active_state === "active" ? (
              <>
                <button onClick={() => onOperation("unit.restart", unit.name)}>{t("Restart")}</button>
                <button onClick={() => onOperation("unit.stop", unit.name)}>{t("Stop")}</button>
              </>
            ) : (
              <button onClick={() => onOperation("unit.start", unit.name)}>{t("Start")}</button>
            )}
            {unit.active_state === "failed" && (
              <button className="secondary" onClick={() => onOperation("unit.reset_failed", unit.name)}>{t("Reset failed")}</button>
            )}
            {/* Enabling changes the host's behaviour after a reboot, so it
                is separate from starting now. */}
            {unit.unit_file_state === "enabled" ? (
              <button onClick={() => onEnable(false)}>{t("Disable")}</button>
            ) : unit.unit_file_state === "disabled" ? (
              <button onClick={() => onEnable(true)}>{t("Enable")}</button>
            ) : null}
            {unit.unit_file_state === "masked" ? (
              <button onClick={onUnmask}>{t("Unmask")}</button>
            ) : (
              <button className="hm-danger" onClick={onMask}>{t("Mask")}</button>
            )}
          </div>
        </Td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={columns.visible.length}>
            <UnitDetailPanel unit={unit} detail={detail} loading={loading} error={error} onRefresh={onRefresh} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The detail of one unit: the facts, the dependencies, the overrides and
 * the last journal lines. Every dependency is a link to its own unit, so the
 * graph is walked link by link rather than read from a dump.
 */
function UnitDetailPanel({
  unit, detail, loading, error, onRefresh,
}: {
  unit: Unit;
  detail?: UnitDetail;
  loading: boolean;
  error: string;
  onRefresh: () => void;
}) {
  const t = useT();
  if (error) {
    return (
      <div className="hm-section-body">
        <Message text={error} error />
        <div className="operations"><button className="secondary" onClick={onRefresh}>{t("Read again")}</button></div>
      </div>
    );
  }
  if (!detail) {
    return (
      <div className="hm-section-body">
        <p className="source" style={{ margin: 0 }}>
          {loading ? t("Reading the unit from the host…") : t("The detail has not been read yet.")}
        </p>
      </div>
    );
  }

  const state = detail.state;
  const dependencies: { label: string; units?: string[] }[] = [
    { label: t("Requires"), units: detail.requires },
    { label: t("Wants"), units: detail.wants },
    { label: t("Bound to"), units: detail.binds_to },
    { label: t("Part of"), units: detail.part_of },
    { label: t("After"), units: detail.after },
    { label: t("Before"), units: detail.before },
  ].filter((group) => group.units && group.units.length > 0);
  const activation: { label: string; units?: string[] }[] = [
    { label: t("Triggered by"), units: detail.triggered_by },
    { label: t("Triggers"), units: detail.triggers },
  ].filter((group) => group.units && group.units.length > 0);
  const lines = detail.journal_lines ?? [];
  const logs = {
    pathname: "../logs",
    search: `?unit=${encodeURIComponent(unit.name)}${detail.journal_cursor ? `&cursor=${encodeURIComponent(detail.journal_cursor)}` : ""}`,
  };

  return (
    <div className="hm-section-body" data-testid="unit-detail">
      <Facts>
        <Fact label={t("Description")} wide>{detail.description || "—"}</Fact>
        <Fact label={t("Unit file")} wide><span className="hm-mono">{detail.fragment_path || "—"}</span></Fact>
        <Fact label={t("State")}>
          <span className={state.active_state === "active" ? "badge ok" : state.active_state === "failed" ? "badge error" : "badge"}>
            {state.active_state}
          </span>{" "}
          {state.sub_state}
          {state.result && state.result !== "success" && <span className="badge warn"> {state.result}</span>}
        </Fact>
        <Fact label={t("Main PID")}>{state.main_pid || "—"}</Fact>
        {/* A restart count above zero is the mark of a unit that keeps
            falling over: "active" alone would hide it. */}
        <Fact label={t("Restarts")}>
          {(state.n_restarts ?? 0) > 0 ? <span className="badge warn">{state.n_restarts}</span> : state.n_restarts ?? "—"}
        </Fact>
        <Fact label={t("Main process started")}>
          {detail.exec_main_start
            ? <span title={absoluteTime(detail.exec_main_start)}><Time value={detail.exec_main_start} /></span>
            : "—"}
        </Fact>
        <Fact label={t("On boot")}>{state.unit_file_state || "—"}</Fact>
      </Facts>

      {/* Every dependency links to its unit: the list narrows to it and
          its own detail opens. */}
      {dependencies.length > 0 && (
        <>
          <p className="widget-subhead">{t("Dependencies")}</p>
          {dependencies.map((group) => (
            <UnitChips key={group.label} label={group.label} units={group.units ?? []} />
          ))}
        </>
      )}
      {activation.length > 0 && (
        <>
          <p className="widget-subhead">{t("Activation")}</p>
          {activation.map((group) => (
            <UnitChips key={group.label} label={group.label} units={group.units ?? []} />
          ))}
        </>
      )}

      <p className="widget-subhead">{t("Drop-ins")}</p>
      {!detail.drop_ins?.length ? (
        <p className="source" style={{ margin: 0 }}>{t("No override files.")}</p>
      ) : (
        (detail.drop_ins ?? []).map((dropIn) => (
          <div key={dropIn.path} style={{ marginBottom: 8 }}>
            <span className="hm-mono">{dropIn.path}</span>
            {dropIn.error ? (
              <span className="badge unknown" title={dropIn.error}> {t("not read")}</span>
            ) : (
              <pre className="hm-log">{dropIn.content}{dropIn.truncated ? `\n… ${t("truncated")}` : ""}</pre>
            )}
          </div>
        ))
      )}

      <p className="widget-subhead">{t("Last journal lines")}</p>
      {detail.journal_error ? (
        <p className="warning"><span>{detail.journal_error}</span></p>
      ) : lines.length === 0 ? (
        <p className="source" style={{ margin: 0 }}>{t("The journal has nothing for this unit.")}</p>
      ) : (
        <pre className="hm-log">{lines.join("\n")}</pre>
      )}
      <div className="operations" style={{ marginTop: 8 }}>
        {/* The Logs page continues right after the last line shown here:
            the cursor travels in the address. */}
        <Link className="button" to={logs}>{t("Follow in Logs")}</Link>
        <button className="secondary" onClick={onRefresh}>{t("Read again")}</button>
        {detail.journal_truncated && <span className="source">{t("output truncated")}</span>}
      </div>
    </div>
  );
}

/** A labelled row of unit chips, each a link to its unit in the list. */
function UnitChips({ label, units }: { label: string; units: string[] }) {
  return (
    <div className="operations" style={{ alignItems: "center", marginBottom: 6 }}>
      <span className="source">{label}</span>
      {units.map((name) => (
        <Link key={name} className="chip chip-mono" to={`?unit=${encodeURIComponent(name)}`}>{name}</Link>
      ))}
    </div>
  );
}
