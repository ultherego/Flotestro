import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { Panel, Cols, Empty, Field, Fields, MoreFilters, Attention, PageHead, Stat, Stats, Toolbar, Verdict } from "./kit";
import { ModuleHeader, Section, Stats as HostStats, Summary, Widgets } from "../pages/host/shared";

/**
 * The header takes its mark from the address and a stat may be a link,
 * so the primitives render inside a router opened at a given address.
 */
function draw(element: ReactElement, at = "/dashboard") {
  return render(<MemoryRouter initialEntries={[at]}>{element}</MemoryRouter>);
}

afterEach(cleanup);

describe("PageHead", () => {
  it("is the header band with the title, the description and the actions", () => {
    const { container, getByRole } = draw(
      <PageHead title="Hosts" description="Every enrolled machine." actions={<button>Add host</button>} />,
      "/hosts",
    );
    const band = container.querySelector("header.ui-pagehead");
    expect(band).not.toBeNull();
    expect(getByRole("heading", { level: 1 })).toHaveTextContent("Hosts");
    expect(container.querySelector(".ui-pagehead-lead")).toHaveTextContent("Every enrolled machine.");
    expect(within(container.querySelector(".ui-pagehead-actions") as HTMLElement).getByRole("button")).toHaveTextContent("Add host");
  });

  it("takes the mark of its section from the address when none is given", () => {
    const { container } = draw(<PageHead title="Audit" />, "/audit?outcome=denied");
    const mark = container.querySelector(".ui-pagehead-mark");
    expect(mark).not.toBeNull();
    expect(mark).toHaveAttribute("aria-hidden", "true");
    expect(mark?.querySelector("svg.ui-icon")).not.toBeNull();
  });

  it("marks the enrolment screen apart from the host list under the same prefix", () => {
    const { container: list } = draw(<PageHead title="Hosts" />, "/hosts");
    const { container: enrol } = draw(<PageHead title="Add host" />, "/hosts/new");
    const path = (root: HTMLElement) => root.querySelector(".ui-pagehead-mark path")?.getAttribute("d");
    expect(path(list)).toBeTruthy();
    expect(path(enrol)).toBeTruthy();
    expect(path(list)).not.toBe(path(enrol));
  });

  it("prefers the mark it is given and draws none for an address it does not know", () => {
    const { container: given } = draw(<PageHead title="Groups" icon="groups" />, "/unknown-place");
    expect(given.querySelector(".ui-pagehead-mark")).not.toBeNull();
    const { container: none } = draw(<PageHead title="Nowhere" />, "/unknown-place");
    expect(none.querySelector(".ui-pagehead-mark")).toBeNull();
  });

  it("draws the breadcrumb as links above the title, and no nav without one", () => {
    const { container, getByRole } = draw(
      <PageHead title="databases-gold" breadcrumb={[{ label: "Groups", to: "/groups" }]} />,
      "/groups/1",
    );
    const nav = container.querySelector("nav.ui-crumbs");
    expect(nav).not.toBeNull();
    expect(getByRole("link", { name: "Groups" })).toHaveAttribute("href", "/groups");
    const { container: bare } = draw(<PageHead title="Groups" breadcrumb={[]} />, "/groups");
    expect(bare.querySelector("nav.ui-crumbs")).toBeNull();
  });
});

describe("Panel", () => {
  it("has a head only when there is something to put in it", () => {
    const { container } = draw(<Panel><p>body</p></Panel>);
    expect(container.querySelector(".ui-panel-head")).toBeNull();
    expect(container.querySelector(".ui-panel-body")).toHaveTextContent("body");
    const { container: titled } = draw(<Panel title="Rules" description="What fires." actions={<button>New</button>} footer="foot">x</Panel>);
    expect(titled.querySelector(".ui-panel-title")).toHaveTextContent("Rules");
    expect(titled.querySelector(".ui-panel-note")).toHaveTextContent("What fires.");
    expect(titled.querySelector(".ui-panel-actions button")).toHaveTextContent("New");
    expect(titled.querySelector(".ui-panel-foot")).toHaveTextContent("foot");
  });

  it("lets a flush table reach the edges and carries the tone and the grid span", () => {
    const { container } = draw(<Panel className="ui-col-8" tone="warn" flush><table /></Panel>);
    const card = container.querySelector("section.ui-panel") as HTMLElement;
    expect(card).toHaveClass("ui-panel", "ui-warn", "ui-col-8");
    expect(container.querySelector(".ui-panel-body")).toHaveClass("ui-flush");
  });

  it("draws no body for nothing, so an empty card is only its head", () => {
    const { container } = draw(<Panel title="Empty">{false}</Panel>);
    expect(container.querySelector(".ui-panel-body")).toBeNull();
    expect(container.querySelector(".ui-panel-title")).toHaveTextContent("Empty");
  });
});

describe("Stat", () => {
  it("shows a missing value as a dash, because unknown is not zero", () => {
    const { container } = draw(<Stat label="Hosts silent" value={null} />);
    expect(container.querySelector(".ui-stat-value")).toHaveTextContent("—");
    expect(container.querySelector(".ui-stat-label")).toHaveTextContent("Hosts silent");
    expect(container.querySelector(".ui-stat-note")).toBeNull();
  });

  it("keeps a number big and gives a phrase a size it fits in", () => {
    const { container: number } = draw(<Stat label="Rules" value={12} hint="as of now" tone="ok" />);
    expect(number.querySelector(".ui-stat-value")).not.toHaveClass("ui-stat-phrase");
    expect(number.querySelector(".ui-stat")).toHaveClass("ui-ok");
    expect(number.querySelector(".ui-stat-note")).toHaveTextContent("as of now");
    const { container: phrase } = draw(<Stat label="Issuer" value="https://sso.example.org" />);
    expect(phrase.querySelector(".ui-stat-value")).toHaveClass("ui-stat-phrase");
  });

  it("is a link as a whole when it has a destination", () => {
    const { getByRole, container } = draw(<Stat label="Offline" value={2} to="/hosts?connection_state=offline" tone="error" />);
    const link = getByRole("link");
    expect(link).toHaveAttribute("href", "/hosts?connection_state=offline");
    expect(link).toHaveClass("ui-stat", "ui-error", "ui-stat-link");
    expect(container.querySelector("div.ui-stat")).toBeNull();
  });

  it("sits in a grid that drops its borders in the compact form", () => {
    const { container } = draw(<Stats compact><Stat label="a" value={1} /></Stats>);
    expect(container.querySelector(".ui-stats")).toHaveClass("ui-compact");
    const { container: plain } = draw(<Stats><Stat label="a" value={1} /></Stats>);
    expect(plain.querySelector(".ui-stats")).not.toHaveClass("ui-compact");
  });
});

describe("Toolbar, Field and the rest", () => {
  it("keeps what is given as end at the right edge", () => {
    const { container } = draw(<Toolbar end={<span>3 hosts</span>}><input /></Toolbar>);
    expect(container.querySelector(".ui-toolbar input")).not.toBeNull();
    expect(container.querySelector(".ui-toolbar-end")).toHaveTextContent("3 hosts");
    const { container: bare } = draw(<Toolbar><input /></Toolbar>);
    expect(bare.querySelector(".ui-toolbar-end")).toBeNull();
  });

  it("labels its control and takes the whole row when wide", () => {
    const { getByLabelText, container } = draw(
      <Fields>
        <Field label="Name" hint="short, no spaces"><input /></Field>
        <Field label="Payload" wide><textarea /></Field>
      </Fields>,
    );
    expect(getByLabelText(/Name/)).toBeInstanceOf(HTMLInputElement);
    expect(container.querySelector(".ui-field-hint")).toHaveTextContent("short, no spaces");
    const fields = container.querySelectorAll(".ui-fields > label.ui-field");
    expect(fields).toHaveLength(2);
    expect(fields[0]).not.toHaveClass("ui-wide");
    expect(fields[1]).toHaveClass("ui-wide");
  });

  it("says in a sentence that a list is empty and offers the action that fills it", () => {
    const { container, getByRole } = draw(<Empty action={<button>New group</button>}>No groups yet.</Empty>);
    expect(container.querySelector(".ui-empty p")).toHaveTextContent("No groups yet.");
    expect(getByRole("button")).toHaveTextContent("New group");
    const { container: plain } = draw(<Empty>Nothing.</Empty>);
    expect(plain.querySelector(".ui-actions")).toBeNull();
  });

  it("puts blocks side by side, wider on request", () => {
    const { container } = draw(<Cols wide><div /><div /></Cols>);
    expect(container.querySelector(".ui-cols")).toHaveClass("ui-wide");
    expect(container.querySelectorAll(".ui-cols > div")).toHaveLength(2);
  });
});

/* The module pages share the twelve-column widget grid with the fleet
   pages: a section names how many columns it spans, and the grid is one
   class every page uses. The tests pin the class names, because the
   stylesheet reads them and a page that forgot one would silently stack. */
describe("the widget grid of a module page", () => {
  it("is one grid, and a section spans the columns it names", () => {
    const { container } = draw(
      <Widgets>
        <Section title="Failed units" span={4}>a</Section>
        <Section title="All units" span={8}>b</Section>
        <Section title="Plain">c</Section>
      </Widgets>,
    );
    const grid = container.querySelector(".ui-grid") as HTMLElement;
    expect(grid).not.toBeNull();
    const sections = grid.querySelectorAll(":scope > section.ui-panel");
    expect(sections).toHaveLength(3);
    expect(sections[0]).toHaveClass("ui-col-4");
    expect(sections[1]).toHaveClass("ui-col-8");
    // A section without a span has no span class at all: the stylesheet
    // gives it the whole row rather than a guess.
    expect(sections[2].className).toBe("ui-panel");
  });

  it("gives a section its title, its count and its tools in the head, and pads the body unless flush", () => {
    const { container } = draw(
      <Section title="Processes" count={12} tools={<input placeholder="Filter" />} description="The slice.">
        <p>rows</p>
      </Section>,
    );
    const head = container.querySelector(".ui-panel-head") as HTMLElement;
    expect(within(head).getByRole("heading", { level: 3 })).toHaveTextContent("Processes");
    expect(head.querySelector(".ui-count")).toHaveTextContent("12");
    expect(head.querySelector(".ui-panel-actions input")).toHaveAttribute("placeholder", "Filter");
    expect(container.querySelector(".ui-panel-note")).toHaveTextContent("The slice.");
    expect(container.querySelector(".ui-panel-body p")).toHaveTextContent("rows");

    const { container: flush } = draw(<Section title="Table" flush><table /></Section>);
    expect(flush.querySelector(".ui-panel-body")).toBeNull();
    expect(flush.querySelector(".ui-panel > table")).not.toBeNull();
    expect(flush.querySelector(".ui-count")).toBeNull();
  });

  it("draws a summary as a status bar in a full-width section by default", () => {
    const { container, getByRole } = draw(
      <Summary title="Unit states" segments={[
        { label: "active", value: 3, tone: "ok" },
        { label: "failed", value: undefined, tone: "error" },
      ]} />,
    );
    expect(container.querySelector(".ui-panel")).toHaveClass("ui-col-12");
    const values = within(getByRole("list")).getAllByTestId("status-bar-value");
    expect(values.map((value) => value.textContent)).toEqual(["3", "—"]);
    const { container: narrower } = draw(<Summary title="x" span={8} segments={[]} />);
    expect(narrower.querySelector(".ui-panel")).toHaveClass("ui-col-8");
  });

  it("lets the stat tiles span the grid too", () => {
    const { container } = draw(<HostStats span={6}><div /></HostStats>);
    expect(container.querySelector(".ui-stats")).toHaveClass("ui-col-6");
    const { container: plain } = draw(<HostStats><div /></HostStats>);
    expect(plain.querySelector(".ui-stats")?.className).toBe("ui-stats");
  });

  it("is headed by the module band with the mark of the module in the address", () => {
    const { container, getByRole } = draw(
      <ModuleHeader title="Services" description="systemd units." actions={<button>Read from host</button>} />,
      "/hosts/h1/services",
    );
    expect(container.querySelector("header.ui-sectionhead")).not.toBeNull();
    expect(getByRole("heading", { level: 2 })).toHaveTextContent("Services");
    expect(container.querySelector(".ui-lede")).toHaveTextContent("systemd units.");
    expect(container.querySelector(".ui-actions button")).toHaveTextContent("Read from host");
    expect(container.querySelector(".ui-sectionhead-mark svg.ui-icon")).not.toBeNull();
    // A segment the registry does not know draws no mark; a given one wins.
    const { container: unknown } = draw(<ModuleHeader title="Nowhere" />, "/hosts/h1/nowhere");
    expect(unknown.querySelector(".ui-sectionhead-mark")).toBeNull();
    const { container: given } = draw(<ModuleHeader title="Nowhere" icon="logs" />, "/hosts/h1/nowhere");
    expect(given.querySelector(".ui-sectionhead-mark")).not.toBeNull();
  });
});

// A card that promises "only what needs a decision" and then shows twelve
// tiles reading zero makes the reader do the filtering the page offered to
// do. The fleet dashboard did exactly that: fifteen tiles, three with a
// number in them.
describe("Stats folding its zeros", () => {
  it("keeps what is there and names what is not", () => {
    const { container, getByTestId } = render(
      <MemoryRouter>
        <Stats foldZeros>
          <Stat label="With failed units" value={1} to="/hosts?failed_units=true" />
          <Stat label="Reboot required" value={0} to="/hosts?reboot_required=true" />
          <Stat label="SSSD offline" value={0} />
        </Stats>
      </MemoryRouter>,
    );
    const tiles = container.querySelectorAll(".ui-stat");
    expect(tiles).toHaveLength(1);
    expect(tiles[0]).toHaveTextContent("With failed units");

    const folded = getByTestId("stats-folded");
    expect(folded).toHaveTextContent("Reboot required");
    expect(folded).toHaveTextContent("SSSD offline");
    // The one that led somewhere still does: a zero is still a question an
    // operator may want to open.
    expect(folded.querySelectorAll("a")).toHaveLength(1);
  });

  it("leaves a tile that never reported in the grid, because unknown is not zero", () => {
    const { container } = render(
      <MemoryRouter>
        <Stats foldZeros>
          <Stat label="Agents unsupported" value={undefined} />
          <Stat label="Reboot required" value={0} />
        </Stats>
      </MemoryRouter>,
    );
    const tiles = container.querySelectorAll(".ui-stat");
    expect(tiles).toHaveLength(1);
    expect(tiles[0]).toHaveTextContent("Agents unsupported");
    expect(tiles[0]).toHaveTextContent("—");
  });

  it("does not fold anything unless the card asks for it", () => {
    const { container } = render(
      <MemoryRouter>
        <Stats>
          <Stat label="Failed units" value={0} />
        </Stats>
      </MemoryRouter>,
    );
    expect(container.querySelectorAll(".ui-stat")).toHaveLength(1);
    expect(container.querySelector(".ui-stats-folded")).toBeNull();
  });
});

// Nineteen controls stood above a table of four hosts. The fold is allowed
// to hide the controls; it is not allowed to hide the fact that one of them
// is narrowing the list.
describe("MoreFilters", () => {
  it("hides the filters until somebody asks for them", () => {
    const { getByTestId, queryByTestId } = render(
      <MemoryRouter>
        <MoreFilters active={false}><input aria-label="relay" /></MoreFilters>
      </MemoryRouter>,
    );
    expect(queryByTestId("more-filters-row")).toBeNull();
    expect(getByTestId("more-filters")).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(getByTestId("more-filters"));
    expect(getByTestId("more-filters-row")).toBeInTheDocument();
  });

  it("opens itself when one of them is set, and says how many", () => {
    const { getByTestId } = render(
      <MemoryRouter>
        <MoreFilters active count={2}><input aria-label="relay" /></MoreFilters>
      </MemoryRouter>,
    );
    // Open, and the button offers to close rather than to open: a list
    // narrowed by a control nobody can see looks wrong for no reason.
    expect(getByTestId("more-filters-row")).toBeInTheDocument();
    expect(getByTestId("more-filters")).toHaveAttribute("aria-expanded", "true");
  });
});

describe("Verdict", () => {
  it("is the headline and its few facts, without a box of its own", () => {
    const { getByTestId } = draw(
      <Verdict tone="ok" headline="Every judged part is fine"><span>all 13 judged</span></Verdict>,
    );
    const zone = getByTestId("verdict");
    expect(zone.className).toContain("ui-ok");
    expect(zone.querySelector(".ui-verdict-headline")).toHaveTextContent("Every judged part is fine");
    expect(zone.querySelector(".ui-verdict-facts")).toHaveTextContent("all 13 judged");
    // Not a card: a card is what the rest of the page is made of.
    expect(zone.classList.contains("ui-panel")).toBe(false);
  });
});

describe("Attention", () => {
  it("draws nothing at all when nothing needs a decision", () => {
    const { queryByTestId } = draw(<Attention title="Needs a look">{[]}</Attention>);
    expect(queryByTestId("needs-attention")).toBeNull();
  });

  it("names what needs one when something does", () => {
    const { getByTestId } = draw(
      <Attention title="Needs a look"><p>Replicas: one is behind</p></Attention>,
    );
    expect(getByTestId("needs-attention")).toHaveTextContent("Replicas: one is behind");
  });
});

describe("the page header's explanation", () => {
  it("keeps the paragraph behind the mark beside the title", () => {
    const { getByTestId, queryByTestId } = draw(
      <PageHead title="Status" description="One line." help={<p>The long explanation.</p>} />,
      "/status",
    );
    expect(queryByTestId("page-help")).toBeNull();
    expect(getByTestId("page-help-toggle")).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(getByTestId("page-help-toggle"));
    expect(getByTestId("page-help")).toHaveTextContent("The long explanation.");
  });

  it("has no mark when a screen has nothing more to say", () => {
    const { queryByTestId } = draw(<PageHead title="Tags" description="One line." />, "/tags");
    expect(queryByTestId("page-help-toggle")).toBeNull();
  });
});
