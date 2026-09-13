import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Icon, type IconName } from "./icons";

/**
 * The layout primitives of a page: the header, the card, the stat tile,
 * the toolbar and the form field. Every fleet page is built from these,
 * so the pages share one rhythm - the same header, the same spacing, the
 * same card around every table - instead of each one inventing its own.
 *
 * They carry no data logic: a page decides what to show, these decide
 * where it stands. The tone of a tile or a card comes from the state
 * tokens (ok, warn, error, unknown); no colour is named here.
 */

export type Tone = "ok" | "warn" | "error" | "unknown";

/** A link on the way to the current page, shown above the title. */
export type Crumb = { label: string; to: string };

/**
 * The page header: the title, what the page is for, and the actions that
 * belong to the whole page. The description is a sentence, not a manual;
 * the detailed explanation goes with the section it explains.
 */
export function PageHeader({
  title, description, actions, breadcrumb, icon,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  breadcrumb?: Crumb[];
  /** The mark of the section; without it the header takes the one of its route. */
  icon?: IconName;
}) {
  const location = useLocation();
  const mark = icon ?? iconForPath(location.pathname);
  return (
    <header className="page-header">
      <div className="page-header-row">
        {mark && <span className="page-mark" aria-hidden="true"><Icon name={mark} /></span>}
        <div className="page-header-text">
          {breadcrumb && breadcrumb.length > 0 && (
            <nav className="breadcrumb">
              {breadcrumb.map((crumb) => (
                <Link key={crumb.to} to={crumb.to}>{crumb.label}</Link>
              ))}
            </nav>
          )}
          <h1 className="page-title">{title}</h1>
          {description && <p className="page-description">{description}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
    </header>
  );
}

/* The mark of a section, by the first segment of its address: the same
   icon the navigation shows, so the header and the sidebar agree. */
const SECTION_ICONS: Record<string, IconName> = {
  dashboard: "dashboard", hosts: "hosts", jobs: "jobs", bulk: "bulk", campaigns: "campaigns",
  security: "security", vulnerabilities: "vulnerabilities", certificates: "certificates",
  secrets: "secrets", backups: "backups", monitoring: "monitoring", directory: "directory",
  access: "access", audit: "audit",
};

function iconForPath(pathname: string): IconName | undefined {
  const [, first, second] = pathname.split("/");
  if (first === "hosts" && second === "new") return "add-host";
  return SECTION_ICONS[first ?? ""];
}

/**
 * A card: a raised panel with an optional title row and footer.
 *
 * A `flush` card lets a table reach its edges; the text and toolbars put
 * in such a card keep their own padding, so a note above a table or an
 * empty state instead of one still stands where the reader expects it.
 */
export function Card({
  title, description, actions, footer, children, flush = false, tone, className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
  children?: ReactNode;
  flush?: boolean;
  tone?: "warn" | "error";
  className?: string;
}) {
  const classes = ["card", tone, className].filter(Boolean).join(" ");
  return (
    <section className={classes}>
      {(title || description || actions) && (
        <div className="card-head">
          <div className="card-head-text">
            {title && <h2 className="card-title">{title}</h2>}
            {description && <p className="card-description">{description}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children !== undefined && children !== null && children !== false && (
        <div className={flush ? "card-body flush" : "card-body"}>{children}</div>
      )}
      {footer && <div className="card-foot">{footer}</div>}
    </section>
  );
}

/**
 * The summary tiles. The `compact` form drops the borders and stands
 * inside a card, where one bordered box inside another would only add
 * lines.
 */
export function StatGrid({ children, compact = false }: { children: ReactNode; compact?: boolean }) {
  return <div className={compact ? "stats compact" : "stats"}>{children}</div>;
}

/**
 * One tile: a label, a big value and, when a number alone would mislead,
 * a hint saying what the number counts. A tile with a destination is a
 * link as a whole.
 */
export function Stat({
  label, value, hint, tone, to,
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
  to?: string;
}) {
  const classes = ["stat", tone].filter(Boolean).join(" ");
  // A phrase is not a number: it gets a size it fits in instead of an ellipsis.
  const phrase = typeof value === "string" && value.length > 8;
  const body = (
    <>
      <span className="stat-label">{label}</span>
      <span className={phrase ? "stat-value text" : "stat-value"}>{value ?? "—"}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </>
  );
  if (to) return <Link to={to} className={`${classes} stat-link`}>{body}</Link>;
  return <div className={classes}>{body}</div>;
}

/**
 * The row of filters, searches and actions above a list. It wraps rather
 * than scrolls; what is given as `end` keeps to the right edge while
 * there is room for it.
 */
export function Toolbar({ children, end }: { children?: ReactNode; end?: ReactNode }) {
  return (
    <div className="toolbar">
      {children}
      {end && <div className="toolbar-end">{end}</div>}
    </div>
  );
}

/**
 * The fields of a form, in columns that fold into one on a narrow
 * screen. A `wide` field takes the whole row: a description, a payload,
 * anything that is read as a line rather than a word.
 */
export function FieldGrid({ children }: { children: ReactNode }) {
  return <div className="field-grid">{children}</div>;
}

export function Field({
  label, hint, wide = false, children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <label className={wide ? "field wide" : "field"}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

/** The buttons of a form or a card, primary first. */
export function Actions({ children }: { children: ReactNode }) {
  return <div className="actions">{children}</div>;
}

/**
 * An empty list says so in one sentence and, where one exists, offers the
 * action that fills it. A blank card looks like a page that did not load.
 */
export function EmptyState({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty empty-state">
      <p>{children}</p>
      {action && <div className="actions">{action}</div>}
    </div>
  );
}

/**
 * Blocks side by side. A page of short cards stacked in one column reads
 * as a strip down the left with nothing beside it; two or three across
 * use the width. On a narrow screen they stack again.
 */
export function Columns({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "columns wide" : "columns"}>{children}</div>;
}
