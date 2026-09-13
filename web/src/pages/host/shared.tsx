import { useState, type ReactNode } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, InventoryFragment, InventoryRevision, Job } from "../../lib/types";
import { Time } from "../../components/ui";
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

/**
 * The module header: the title, one line on what the module shows and the
 * module's primary actions. The actions live here on every page, so the
 * operator does not hunt for "read from host" at a different place in
 * every module.
 */
export function ModuleHeader({
  title, description, actions,
}: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="hm-header">
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
  title, count, tools, description, flush, children,
}: {
  title: ReactNode;
  count?: number;
  tools?: ReactNode;
  description?: ReactNode;
  flush?: boolean;
  children: ReactNode;
}) {
  return (
    <section className="hm-section">
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
export function Stats({ children }: { children: ReactNode }) {
  return <div className="hm-stats">{children}</div>;
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
    <p className="hm-freshness">
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
  host, description, action, payload, label,
}: { host: Host; description: string; action: string; payload: unknown; label: string }) {
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
    <Section title={t("Request an operation")} description={description}>
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
