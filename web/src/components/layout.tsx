import { Children, isValidElement, useState, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Icon, type IconName } from "./icons";
import { pageTitle, useDocumentTitle } from "../lib/title";
import { useT } from "../i18n";

/**
 * The layout primitives of a page: the header, the card, the stat tile, the
 * toolbar and the form field.
 */

export type Tone = "ok" | "warn" | "error" | "unknown";

/** A link on the way to the current page, shown above the title. */
export type Crumb = { label: string; to: string };

/**
 * The page header: the title, what the page is for, and the actions that
 * belong to the whole page.
 */
export function PageHeader({
  title, description, help, actions, breadcrumb, icon,
}: {
  title: ReactNode;
  /** One line, at most about eighty characters: what this page is for. */
  description?: ReactNode;
  /**
   * The rest of the explanation, behind a mark beside the title. A paragraph
   * is read once and takes the top of the page every time after that, so it
   * waits here until somebody asks for it.
   */
  help?: ReactNode;
  actions?: ReactNode;
  breadcrumb?: Crumb[];
  /** The mark of the section; without it the header takes the one of its route. */
  icon?: IconName;
}) {
  const t = useT();
  const [helpOpen, setHelpOpen] = useState(false);
  const location = useLocation();
  const mark = icon ?? iconForPath(location.pathname);
  // The tab is named after the page.
  useDocumentTitle(typeof title === "string" && title.trim() !== "" ? pageTitle(title) : undefined);
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
          <h1 className="page-title">
            {title}
            {help && (
              <button
                type="button"
                className="page-help-toggle"
                aria-expanded={helpOpen}
                title={t("What this screen is for")}
                onClick={() => setHelpOpen(!helpOpen)}
                data-testid="page-help-toggle"
              >
                <Icon name="help" />
              </button>
            )}
          </h1>
          {description && <p className="page-description">{description}</p>}
          {help && helpOpen && <div className="page-help" data-testid="page-help">{help}</div>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
    </header>
  );
}

/**
 * The head of a section inside a page: a title, one line about it, the rest
 * behind the mark, and the actions on the right.
 *
 * The same object as PageHeader and deliberately a smaller one. A page has a
 * header; a tab of a page has this. Written when the settings screen became
 * an area with tabs and six screens moved into it: each of them had been a
 * page with a header of its own, and the alternative to this was six
 * different ways of putting a title over a tab.
 */
export function SectionHead({
  title, description, help, actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  help?: ReactNode;
  actions?: ReactNode;
}) {
  const t = useT();
  const [helpOpen, setHelpOpen] = useState(false);
  return (
    <>
      <div className="parts-head">
        <h2>
          {title}
          {help && (
            <button
              type="button"
              className="page-help-toggle"
              aria-expanded={helpOpen}
              title={t("What this screen is for")}
              onClick={() => setHelpOpen(!helpOpen)}
              data-testid="section-help-toggle"
            >
              <Icon name="help" />
            </button>
          )}
        </h2>
        {description && <span className="source">{description}</span>}
        {actions && <div className="parts-head-actions">{actions}</div>}
      </div>
      {help && helpOpen && <div className="page-help" data-testid="section-help">{help}</div>}
    </>
  );
}

/* The mark of a section, by the first segment of its address: the same
   icon the navigation shows, so the header and the sidebar agree. */
const SECTION_ICONS: Record<string, IconName> = {
  dashboard: "dashboard", hosts: "hosts", jobs: "jobs", bulk: "bulk", campaigns: "campaigns",
  security: "security", vulnerabilities: "vulnerabilities", certificates: "certificates",
  secrets: "secrets", backups: "backups", monitoring: "monitoring", directory: "directory",
  access: "access", audit: "audit",
  // The sixteen sections this table did not know, every one of them a tab
  // whose title stood with nothing beside it. The icon is the one the
  // navigation already gives that route, so the header and the sidebar say
  // the same thing about the same place - which is the whole reason this
  // table exists rather than each page naming its own.
  groups: "groups", tags: "groups", teams: "accounts", profile: "accounts",
  relays: "relays", reports: "audit", readiness: "overview", policies: "security",
  notifications: "notifications", unresolved: "jobs", reads: "reads", budgets: "overview",
  settings: "settings", status: "settings", setup: "settings", support: "logs",
};

function iconForPath(pathname: string): IconName | undefined {
  const [, first, second] = pathname.split("/");
  if (first === "hosts" && second === "new") return "add-host";
  return SECTION_ICONS[first ?? ""];
}

/**
 * A card: a raised panel with an optional title row and footer.
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
 * The summary tiles. The `compact` form drops the borders and stands inside
 * a card, where one bordered box inside another would only add lines.
 *
 * `foldZeros` is for a grid whose card promises to show what needs doing.
 * The fleet dashboard says "Only what needs a decision" over fifteen tiles
 * of which twelve read zero, so the eye has to sweep all fifteen to find the
 * one and the seven. With it on, a tile at zero becomes a word under the
 * grid and the tiles are the things that are actually there.
 *
 * It is not the default, and should not be: on a host's own page "0 failed
 * units" is the answer somebody came for. A zero is noise only where the
 * card has promised otherwise.
 *
 * Unknown is not zero. A tile whose value never arrived keeps its place in
 * the grid, because "we do not know" is exactly what such a card is for.
 */
export function StatGrid({
  children, compact = false, foldZeros = false,
}: {
  children: ReactNode;
  compact?: boolean;
  foldZeros?: boolean;
}) {
  const classes = compact ? "stats compact" : "stats";
  if (!foldZeros) return <div className={classes}>{children}</div>;

  const tiles: ReactNode[] = [];
  const folded: { label: ReactNode; to?: string }[] = [];
  Children.forEach(children, (child) => {
    if (!isValidElement<{ value?: unknown; label?: ReactNode; to?: string }>(child)) {
      tiles.push(child);
      return;
    }
    if (child.props.value === 0) {
      folded.push({ label: child.props.label, to: child.props.to });
      return;
    }
    tiles.push(child);
  });

  return (
    <>
      {tiles.length > 0 && <div className={classes}>{tiles}</div>}
      {folded.length > 0 && (
        <div className="stats-folded" data-testid="stats-folded">
          {folded.map((one, index) => {
            const body = <><span className="stats-folded-value">0</span>{one.label}</>;
            return one.to
              ? <Link key={index} to={one.to} className="stats-folded-item">{body}</Link>
              : <span key={index} className="stats-folded-item">{body}</span>;
          })}
        </div>
      )}
    </>
  );
}

/**
 * One tile: a label, a big value and, when a number alone would mislead, a
 * hint saying what the number counts.
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
 * The filters a list keeps out of the way until somebody wants them.
 *
 * The host list carries nineteen controls in five rows above a table that,
 * in this laboratory, holds four rows. That is about 200 px of machinery
 * before the first piece of data, on the page whose job is the data.
 *
 * `active` is the page's own answer to "is any of these set?", and when it
 * is true the block opens and stays open. That rule is the whole point: a
 * filter that is narrowing the list must be visible, or the reader sees a
 * short list and no reason for it. Hiding the controls is allowed; hiding
 * the fact that they are working is not.
 */
export function MoreFilters({
  active, count, children,
}: {
  /** Whether any of the folded filters is set. */
  active: boolean;
  /** How many of them are set, for the button. */
  count?: number;
  children: ReactNode;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const shown = open || active;
  return (
    <>
      <button
        type="button"
        className={shown ? "secondary more-filters open" : "secondary more-filters"}
        aria-expanded={shown}
        onClick={() => setOpen(!shown)}
        data-testid="more-filters"
      >
        {shown ? t("Fewer filters") : t("More filters")}
        {!shown && count ? <span className="badge warn">{count}</span> : null}
      </button>
      {shown && <div className="more-filters-row" data-testid="more-filters-row">{children}</div>}
    </>
  );
}

/**
 * The row of filters, searches and actions above a list.
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
 * The fields of a form, in columns that fold into one on a narrow screen.
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
 * Blocks side by side.
 */
export function Columns({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "columns wide" : "columns"}>{children}</div>;
}

/* ---------------------------------------------------------------------- */
/* The three zones of a page: the verdict, what needs a decision, and the  */
/* detail. Nothing else belongs at the top level of a screen.              */
/* ---------------------------------------------------------------------- */

/**
 * The answer the page exists to give, in one line and without a border.
 *
 * A screen that opens with sixteen bordered boxes of equal weight has no
 * entry point: the eye has nowhere to land and every box asks to be read.
 * This is the one thing that is read first, so it is the one thing that is
 * not in a box.
 */
export function Verdict({
  tone, headline, children, actions,
}: {
  tone?: Tone;
  /** The sentence or the number that answers the page's question. */
  headline: ReactNode;
  /** The few facts that qualify it; three or four, not a list. */
  children?: ReactNode;
  actions?: ReactNode;
}) {
  const classes = ["verdict", tone].filter(Boolean).join(" ");
  return (
    <section className={classes} data-testid="verdict">
      <div className="verdict-row">
        <p className="verdict-headline">{headline}</p>
        {actions && <div className="verdict-actions">{actions}</div>}
      </div>
      {children && <div className="verdict-facts">{children}</div>}
    </section>
  );
}

/**
 * What the reader has to do something about. The zone draws nothing at all
 * when it is empty, which is the point: an empty heading reads as a thing
 * the page is still loading.
 */
export function NeedsAttention({ title, children }: { title: ReactNode; children?: ReactNode }) {
  const count = Children.toArray(children).filter(Boolean).length;
  if (count === 0) return null;
  return (
    <section className="needs-attention" data-testid="needs-attention">
      <h2 className="needs-attention-title">{title}</h2>
      <div className="needs-attention-body">{children}</div>
    </section>
  );
}
