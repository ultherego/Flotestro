import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { Card, Columns, EmptyState, Field, FieldGrid, PageHeader, Stat, StatGrid, Toolbar } from "./layout";
import { ModuleHeader, Section, Stats, Summary, Widgets } from "../pages/host/shared";

/**
 * The header takes its mark from the address and a stat may be a link,
 * so the primitives render inside a router opened at a given address.
 */
function draw(element: ReactElement, at = "/dashboard") {
  return render(<MemoryRouter initialEntries={[at]}>{element}</MemoryRouter>);
}

afterEach(cleanup);

describe("PageHeader", () => {
  it("is the header band with the title, the description and the actions", () => {
    const { container, getByRole } = draw(
      <PageHeader title="Hosts" description="Every enrolled machine." actions={<button>Add host</button>} />,
      "/hosts",
    );
    const band = container.querySelector("header.page-header");
    expect(band).not.toBeNull();
    expect(getByRole("heading", { level: 1 })).toHaveTextContent("Hosts");
    expect(container.querySelector(".page-description")).toHaveTextContent("Every enrolled machine.");
    expect(within(container.querySelector(".page-actions") as HTMLElement).getByRole("button")).toHaveTextContent("Add host");
  });

  it("takes the mark of its section from the address when none is given", () => {
    const { container } = draw(<PageHeader title="Audit" />, "/audit?outcome=denied");
    const mark = container.querySelector(".page-mark");
    expect(mark).not.toBeNull();
    expect(mark).toHaveAttribute("aria-hidden", "true");
    expect(mark?.querySelector("svg.icon")).not.toBeNull();
  });

  it("marks the enrolment screen apart from the host list under the same prefix", () => {
    const { container: list } = draw(<PageHeader title="Hosts" />, "/hosts");
    const { container: enrol } = draw(<PageHeader title="Add host" />, "/hosts/new");
    const path = (root: HTMLElement) => root.querySelector(".page-mark path")?.getAttribute("d");
    expect(path(list)).toBeTruthy();
    expect(path(enrol)).toBeTruthy();
    expect(path(list)).not.toBe(path(enrol));
  });

  it("prefers the mark it is given and draws none for an address it does not know", () => {
    const { container: given } = draw(<PageHeader title="Groups" icon="groups" />, "/unknown-place");
    expect(given.querySelector(".page-mark")).not.toBeNull();
    const { container: none } = draw(<PageHeader title="Nowhere" />, "/unknown-place");
    expect(none.querySelector(".page-mark")).toBeNull();
  });

  it("draws the breadcrumb as links above the title, and no nav without one", () => {
    const { container, getByRole } = draw(
      <PageHeader title="databases-gold" breadcrumb={[{ label: "Groups", to: "/groups" }]} />,
      "/groups/1",
    );
    const nav = container.querySelector("nav.breadcrumb");
    expect(nav).not.toBeNull();
    expect(getByRole("link", { name: "Groups" })).toHaveAttribute("href", "/groups");
    const { container: bare } = draw(<PageHeader title="Groups" breadcrumb={[]} />, "/groups");
    expect(bare.querySelector("nav.breadcrumb")).toBeNull();
  });
});

describe("Card", () => {
  it("has a head only when there is something to put in it", () => {
    const { container } = draw(<Card><p>body</p></Card>);
    expect(container.querySelector(".card-head")).toBeNull();
    expect(container.querySelector(".card-body")).toHaveTextContent("body");
    const { container: titled } = draw(<Card title="Rules" description="What fires." actions={<button>New</button>} footer="foot">x</Card>);
    expect(titled.querySelector(".card-title")).toHaveTextContent("Rules");
    expect(titled.querySelector(".card-description")).toHaveTextContent("What fires.");
    expect(titled.querySelector(".card-actions button")).toHaveTextContent("New");
    expect(titled.querySelector(".card-foot")).toHaveTextContent("foot");
  });

  it("lets a flush table reach the edges and carries the tone and the grid span", () => {
    const { container } = draw(<Card className="span-8" tone="warn" flush><table /></Card>);
    const card = container.querySelector("section.card") as HTMLElement;
    expect(card).toHaveClass("card", "warn", "span-8");
    expect(container.querySelector(".card-body")).toHaveClass("flush");
  });

  it("draws no body for nothing, so an empty card is only its head", () => {
    const { container } = draw(<Card title="Empty">{false}</Card>);
    expect(container.querySelector(".card-body")).toBeNull();
    expect(container.querySelector(".card-title")).toHaveTextContent("Empty");
  });
});

describe("Stat", () => {
  it("shows a missing value as a dash, because unknown is not zero", () => {
    const { container } = draw(<Stat label="Hosts silent" value={null} />);
    expect(container.querySelector(".stat-value")).toHaveTextContent("—");
    expect(container.querySelector(".stat-label")).toHaveTextContent("Hosts silent");
    expect(container.querySelector(".stat-hint")).toBeNull();
  });

  it("keeps a number big and gives a phrase a size it fits in", () => {
    const { container: number } = draw(<Stat label="Rules" value={12} hint="as of now" tone="ok" />);
    expect(number.querySelector(".stat-value")).not.toHaveClass("text");
    expect(number.querySelector(".stat")).toHaveClass("ok");
    expect(number.querySelector(".stat-hint")).toHaveTextContent("as of now");
    const { container: phrase } = draw(<Stat label="Issuer" value="https://sso.example.org" />);
    expect(phrase.querySelector(".stat-value")).toHaveClass("text");
  });

  it("is a link as a whole when it has a destination", () => {
    const { getByRole, container } = draw(<Stat label="Offline" value={2} to="/hosts?connection_state=offline" tone="error" />);
    const link = getByRole("link");
    expect(link).toHaveAttribute("href", "/hosts?connection_state=offline");
    expect(link).toHaveClass("stat", "error", "stat-link");
    expect(container.querySelector("div.stat")).toBeNull();
  });

  it("sits in a grid that drops its borders in the compact form", () => {
    const { container } = draw(<StatGrid compact><Stat label="a" value={1} /></StatGrid>);
    expect(container.querySelector(".stats")).toHaveClass("compact");
    const { container: plain } = draw(<StatGrid><Stat label="a" value={1} /></StatGrid>);
    expect(plain.querySelector(".stats")).not.toHaveClass("compact");
  });
});

describe("Toolbar, Field and the rest", () => {
  it("keeps what is given as end at the right edge", () => {
    const { container } = draw(<Toolbar end={<span>3 hosts</span>}><input /></Toolbar>);
    expect(container.querySelector(".toolbar input")).not.toBeNull();
    expect(container.querySelector(".toolbar-end")).toHaveTextContent("3 hosts");
    const { container: bare } = draw(<Toolbar><input /></Toolbar>);
    expect(bare.querySelector(".toolbar-end")).toBeNull();
  });

  it("labels its control and takes the whole row when wide", () => {
    const { getByLabelText, container } = draw(
      <FieldGrid>
        <Field label="Name" hint="short, no spaces"><input /></Field>
        <Field label="Payload" wide><textarea /></Field>
      </FieldGrid>,
    );
    expect(getByLabelText(/Name/)).toBeInstanceOf(HTMLInputElement);
    expect(container.querySelector(".field-hint")).toHaveTextContent("short, no spaces");
    const fields = container.querySelectorAll(".field-grid > label.field");
    expect(fields).toHaveLength(2);
    expect(fields[0]).not.toHaveClass("wide");
    expect(fields[1]).toHaveClass("wide");
  });

  it("says in a sentence that a list is empty and offers the action that fills it", () => {
    const { container, getByRole } = draw(<EmptyState action={<button>New group</button>}>No groups yet.</EmptyState>);
    expect(container.querySelector(".empty-state p")).toHaveTextContent("No groups yet.");
    expect(getByRole("button")).toHaveTextContent("New group");
    const { container: plain } = draw(<EmptyState>Nothing.</EmptyState>);
    expect(plain.querySelector(".actions")).toBeNull();
  });

  it("puts blocks side by side, wider on request", () => {
    const { container } = draw(<Columns wide><div /><div /></Columns>);
    expect(container.querySelector(".columns")).toHaveClass("wide");
    expect(container.querySelectorAll(".columns > div")).toHaveLength(2);
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
    const grid = container.querySelector(".widgets") as HTMLElement;
    expect(grid).not.toBeNull();
    const sections = grid.querySelectorAll(":scope > section.hm-section");
    expect(sections).toHaveLength(3);
    expect(sections[0]).toHaveClass("span-4");
    expect(sections[1]).toHaveClass("span-8");
    // A section without a span has no span class at all: the stylesheet
    // gives it the whole row rather than a guess.
    expect(sections[2].className).toBe("hm-section");
  });

  it("gives a section its title, its count and its tools in the head, and pads the body unless flush", () => {
    const { container } = draw(
      <Section title="Processes" count={12} tools={<input placeholder="Filter" />} description="The slice.">
        <p>rows</p>
      </Section>,
    );
    const head = container.querySelector(".hm-section-head") as HTMLElement;
    expect(within(head).getByRole("heading", { level: 3 })).toHaveTextContent("Processes");
    expect(head.querySelector(".hm-count")).toHaveTextContent("12");
    expect(head.querySelector(".hm-tools input")).toHaveAttribute("placeholder", "Filter");
    expect(container.querySelector(".hm-section-desc")).toHaveTextContent("The slice.");
    expect(container.querySelector(".hm-section-body p")).toHaveTextContent("rows");

    const { container: flush } = draw(<Section title="Table" flush><table /></Section>);
    expect(flush.querySelector(".hm-section-body")).toBeNull();
    expect(flush.querySelector(".hm-section > table")).not.toBeNull();
    expect(flush.querySelector(".hm-count")).toBeNull();
  });

  it("draws a summary as a status bar in a full-width section by default", () => {
    const { container, getByRole } = draw(
      <Summary title="Unit states" segments={[
        { label: "active", value: 3, tone: "ok" },
        { label: "failed", value: undefined, tone: "error" },
      ]} />,
    );
    expect(container.querySelector(".hm-section")).toHaveClass("span-12");
    const values = within(getByRole("list")).getAllByTestId("status-bar-value");
    expect(values.map((value) => value.textContent)).toEqual(["3", "—"]);
    const { container: narrower } = draw(<Summary title="x" span={8} segments={[]} />);
    expect(narrower.querySelector(".hm-section")).toHaveClass("span-8");
  });

  it("lets the stat tiles span the grid too", () => {
    const { container } = draw(<Stats span={6}><div /></Stats>);
    expect(container.querySelector(".hm-stats")).toHaveClass("span-6");
    const { container: plain } = draw(<Stats><div /></Stats>);
    expect(plain.querySelector(".hm-stats")?.className).toBe("hm-stats");
  });

  it("is headed by the module band with the mark of the module in the address", () => {
    const { container, getByRole } = draw(
      <ModuleHeader title="Services" description="systemd units." actions={<button>Read from host</button>} />,
      "/hosts/h1/services",
    );
    expect(container.querySelector("header.hm-header")).not.toBeNull();
    expect(getByRole("heading", { level: 2 })).toHaveTextContent("Services");
    expect(container.querySelector(".hm-lede")).toHaveTextContent("systemd units.");
    expect(container.querySelector(".hm-actions button")).toHaveTextContent("Read from host");
    expect(container.querySelector(".hm-mark svg.icon")).not.toBeNull();
    // A segment the registry does not know draws no mark; a given one wins.
    const { container: unknown } = draw(<ModuleHeader title="Nowhere" />, "/hosts/h1/nowhere");
    expect(unknown.querySelector(".hm-mark")).toBeNull();
    const { container: given } = draw(<ModuleHeader title="Nowhere" icon="logs" />, "/hosts/h1/nowhere");
    expect(given.querySelector(".hm-mark")).not.toBeNull();
  });
});
