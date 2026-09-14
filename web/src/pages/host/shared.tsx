import { useState, type ReactNode } from "react";
import { Link, useLocation, useOutletContext } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { awaitJob } from "../../lib/jobs";
import type { Host, InventoryFragment, InventoryRevision, Job } from "../../lib/types";
import { Time } from "../../components/ui";
import { Icon, type IconName } from "../../components/icons";
import { StatusBar, type Segment, type WidgetTone } from "../../components/widgets";
import { module as moduleOf } from "./modules";
import { useT } from "../../i18n";

/** The host context comes from the layout, so a tab does not fetch it again. */
export function useHost(): Host {
  return useOutletContext<{ host: Host }>().host;
}

/** The inventory is shared by the tabs, so it shares one cache key. */
export function useInventory(hostID: string) {
  return useQuery({
    queryKey: ["inventory", hostID],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${hostID}/inventory`),
    retry: false,
  });
}

/**
 * A tab fetches its own inventory module. Each has its own revision and its
 * own observation timestamp, so the freshness describes what the operator
 * looks at, not the whole host report.
 */
export function useModule<T>(hostID: string, module: string) {
  return useQuery({
    queryKey: ["inventory", hostID, module],
    queryFn: () => api.get<InventoryFragment<T>>(`/api/v1/hosts/${hostID}/inventory/${module}`),
    retry: false,
  });
}

/**
 * A read whose answer lands in the inventory - the full list of the units,
 * the snapshot of the processes - is settled when the job is over, not when
 * it is queued: the order answers at once, the host later, and the module
 * is written right before the result. The hook follows the job and refetches
 * the modules then, so the listing appears when it exists rather than at the
 * next timed refetch. A job that does not land in time - one waiting for
 * approval, say - is left to that refetch.
 */
export function useModuleRefresh(hostID: string, modules: string[]) {
  const queryClient = useQueryClient();
  return (job: Job) => {
    void awaitJob(api, job.id).then(() => {
      queryClient.invalidateQueries({ queryKey: ["jobs", hostID] });
      for (const module of modules) {
        queryClient.invalidateQueries({ queryKey: ["inventory", hostID, module] });
      }
      // The API answering with an error is not the screen's to report here:
      // the job list shows the job, and the refetch comes on its own.
    }, () => undefined);
  };
}

/* ---------------------------------------------------------------------- */
/* The module page pattern.                                                */
/*                                                                         */
/* Every module is built from the same parts: a header, a freshness line,  */
/* summary tiles where numbers matter and titled sections. The parts are   */
/* components rather than a convention, so a page cannot drift from the    */
/* pattern by forgetting a class.                                          */
/* ---------------------------------------------------------------------- */

/** The page wrapper: it spaces the header, the tiles and the sections. */
export function ModulePage({ children }: { children: ReactNode }) {
  return <div className="hm-page">{children}</div>;
}

/** How many of the twelve columns of the widget grid a block takes. */
export type Span = 3 | 4 | 5 | 6 | 7 | 8 | 9 | 12;

/**
 * The widget grid of a module page: twelve columns, and every section says
 * how many it spans. Short blocks sit beside each other instead of each
 * taking a row of its own with nothing at its right.
 */
export function Widgets({ children }: { children: ReactNode }) {
  return <div className="widgets">{children}</div>;
}

/**
 * The summary of a page: a status bar in a section, read before the list
 * below it. An unknown count is a dash there, never a zero.
 */
export function Summary({
  title, description, span = 12, segments, compact, children,
}: {
  title: ReactNode;
  description?: ReactNode;
  span?: Span;
  segments: Segment[];
  compact?: boolean;
  children?: ReactNode;
}) {
  return (
    <Section title={title} description={description} span={span}>
      <StatusBar segments={segments} compact={compact} />
      {children}
    </Section>
  );
}

/**
 * The tone of a share of a whole: a filesystem or a memory at four fifths
 * is a warning, at nine tenths an error. An undetermined share is not a
 * state at all and stays neutral.
 */
export function usageTone(used?: number, total?: number): WidgetTone {
  if (used === undefined || total === undefined || total <= 0) return "neutral";
  const share = used / total;
  if (share >= 0.9) return "error";
  if (share >= 0.8) return "warn";
  return "ok";
}

/** A count of the items that satisfy a test, or undefined when the list itself is unknown. */
export function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/**
 * The module header: a band with the module's mark on an accent tile, the
 * title, one line on what the module shows and the module's primary
 * actions. The actions live here on every page, so the operator does not
 * hunt for "read from host" at a different place in every module. The mark
 * is the one of the module in the registry, found from the address, so a
 * page does not have to name it.
 */
export function ModuleHeader({
  title, description, actions, icon,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  /** The mark of the module; without it the header takes the one of its route. */
  icon?: IconName;
}) {
  const location = useLocation();
  // The address is /hosts/:id/<segment>; the segment names the module.
  const mark = icon ?? moduleOf(location.pathname.split("/")[3] ?? "")?.icon;
  return (
    <header className="hm-header">
      {mark && <span className="hm-mark" aria-hidden="true"><Icon name={mark} /></span>}
      <div className="hm-header-text">
        <h2 className="hm-title">{title}</h2>
        {description && <p className="hm-lede">{description}</p>}
      </div>
      {actions && <div className="hm-actions">{actions}</div>}
    </header>
  );
}

/**
 * A titled section. The count beside the title says how many rows it holds;
 * the tools (a filter, a toggle, a secondary action) sit at its right edge.
 * The body is padded unless the content is a table, which runs edge to
 * edge and brings its own inset.
 */
export function Section({
  title, count, tools, description, flush, span, children,
}: {
  title: ReactNode;
  count?: number;
  tools?: ReactNode;
  description?: ReactNode;
  flush?: boolean;
  /** The columns of the widget grid the section takes when it stands on one. */
  span?: Span;
  children: ReactNode;
}) {
  return (
    <section className={span ? `hm-section span-${span}` : "hm-section"}>
      <header className="hm-section-head">
        <h3>{title}</h3>
        {count !== undefined && <span className="hm-count">{count}</span>}
        {tools && <div className="hm-tools">{tools}</div>}
      </header>
      {description && <p className="hm-section-desc">{description}</p>}
      {flush ? children : <div className="hm-section-body">{children}</div>}
    </section>
  );
}

/** A table inside a section: the wrapper scrolls sideways, the page never does. */
export function Table({ keyed, children }: { keyed?: boolean; children: ReactNode }) {
  return (
    <div className={keyed ? "hm-table keyed" : "hm-table"}>
      <table>{children}</table>
    </div>
  );
}

/** The quiet line under a table: counts, origin, the observation time. */
export function Foot({ children }: { children: ReactNode }) {
  return <p className="hm-foot">{children}</p>;
}

/** Key/value facts as a grid: the label over the value. */
export function Facts({ children }: { children: ReactNode }) {
  return <dl className="hm-facts">{children}</dl>;
}

export function Fact({ label, wide, children }: { label: ReactNode; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? "hm-fact wide" : "hm-fact"}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** Summary tiles: the numbers that decide whether the rest is worth reading. */
export function Stats({ span, children }: { span?: Span; children: ReactNode }) {
  return <div className={span ? `hm-stats span-${span}` : "hm-stats"}>{children}</div>;
}

export function Stat({
  label, value, hint, tone,
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  /** The state colour of the value; none means a plain number. */
  tone?: "ok" | "warn" | "error" | "unknown";
}) {
  return (
    <div className={tone ? `hm-stat ${tone}` : "hm-stat"}>
      <span className="hm-stat-label">{label}</span>
      <span className="hm-stat-value">{value}</span>
      {hint && <span className="hm-stat-hint">{hint}</span>}
    </div>
  );
}

/** An undetermined number in a tile: unknown is not zero. */
export function Unknown() {
  const t = useT();
  return <span className="badge unknown">{t("unknown")}</span>;
}

/**
 * The outcome of the last request: the job id or the error. Nothing is
 * rendered while there is nothing to say, so the layout does not jump.
 */
export function Message({ text, error }: { text: string; error?: boolean }) {
  if (!text) return null;
  return <p className={error ? "hm-message error" : "hm-message"}>{text}</p>;
}

/** A form: fields in a grid, then the actions. */
export function Form({ children }: { children: ReactNode }) {
  return <div className="hm-form">{children}</div>;
}

export function Fields({ children }: { children: ReactNode }) {
  return <div className="hm-fields">{children}</div>;
}

/** A labelled field with optional help text under the control. */
export function Field({
  label, help, wide, narrow, children,
}: { label: ReactNode; help?: ReactNode; wide?: boolean; narrow?: boolean; children: ReactNode }) {
  const className = ["hm-field", wide ? "wide" : "", narrow ? "narrow" : ""].filter(Boolean).join(" ");
  return (
    <label className={className}>
      <span className="hm-field-label">{label}</span>
      {children}
      {help && <span className="hm-field-help">{help}</span>}
    </label>
  );
}

/** A checkbox with its sentence. */
export function Check({
  checked, onChange, disabled, children,
}: { checked: boolean; onChange: (value: boolean) => void; disabled?: boolean; children: ReactNode }) {
  return (
    <label className="hm-check">
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}

export function FormActions({ children }: { children: ReactNode }) {
  return <div className="hm-form-actions">{children}</div>;
}

/** A sentence under the form that the operator is to read before submitting. */
export function FormNote({ children }: { children: ReactNode }) {
  return <p className="hm-form-note">{children}</p>;
}

/**
 * The freshness line: where the data comes from and how fresh it is. An
 * unread module says why - an empty module and an unread module are two
 * different things.
 */
export function ModuleFreshness({ fragment }: { fragment?: InventoryFragment<unknown> }) {
  const t = useT();
  if (!fragment) return null;
  return (
    <p className="hm-freshness" data-testid="module-freshness">
      <span>
        {t("Source: {source}, revision {revision}, observed", { source: fragment.source, revision: fragment.revision.slice(0, 12) })}{" "}
        <Time value={fragment.observed_at} />
      </span>
      {fragment.unavailable_reason && (
        <span className="unread">{t("could not be read: {reason}", { reason: fragment.unavailable_reason })}</span>
      )}
    </p>
  );
}

/**
 * Ordering an operation leads to a plan, not to an immediate change. A
 * mutating operation lands in the awaiting-approval state.
 */
export function RequestOperation({
  host, description, action, payload, label, span,
}: { host: Host; description: string; action: string; payload: unknown; label: string; span?: Span }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [result, setResult] = useState<string>("");

  const mutation = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action, payload }),
    onSuccess: (job) => {
      setResult(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setResult(error instanceof Error ? error.message : String(error)),
  });

  return (
    <Section title={t("Request an operation")} description={description} span={span}>
      {/* The target repeated right at the button: the operator approves a
          specific machine, not "the host I think I have open". */}
      <p className="source" style={{ margin: 0 }}>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </p>
      <FormActions>
        <button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          {mutation.isPending ? t("Requesting…") : label}
        </button>
        <Link to="/jobs">{t("See all jobs")}</Link>
      </FormActions>
      <Message text={result} />
    </Section>
  );
}

/** One attempt of a job as a result view reads it: the status, the refusal and the typed detail. */
export type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/**
 * A read ordered through a job.
 *
 * The order goes out, the screen polls the attempts until the host answers,
 * and the last attempt is the result. The hook keeps the job identifier and
 * the error of the order; the page decides what the detail looks like. A
 * refusal is a result too: the attempt carries the reason, and the page is
 * to show it rather than an empty list.
 */
export function useReadOperation<T>(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<T>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items?.[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  return {
    /** Places the order; the body is the operation request as the API takes it. */
    order: order.mutate,
    /** Whether any order was placed since the last reset. */
    ordered: job !== "",
    /** Whether an answer is still on its way. */
    busy: order.isPending || (job !== "" && !last?.status),
    /** The error of placing the order, empty when it went through. */
    message,
    /** The last attempt once the host answered; undefined until then. */
    attempt: last?.status ? last : undefined,
    reset: () => {
      setJob("");
      setMessage("");
    },
  };
}
