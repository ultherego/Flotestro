import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { Host, Whoami } from "../lib/types";
import { SCALES, useScale, type Scale } from "../lib/scale";
import { Topbar, type Trail } from "./Topbar";

/* The host search in the bar queries the API and needs a query client; it
   is not what these tests look at, so it is replaced by a marker. */
vi.mock("./HostPicker", () => ({
  HostPicker: () => <div data-testid="host-picker" />,
}));

const KEY = "flotestro.scale";

const user: Whoami = {
  subject: "alice@example.org",
  display_name: "Alice",
  kind: "user",
  roles: ["operator"],
  bindings: [],
  permissions: [],
};

const host = {
  id: "h1",
  hostname: "web-01",
  connection_state: "online",
  management_address: "10.0.0.5",
} as Host;

/**
 * The bar as the application mounts it: the text size comes from the hook
 * that remembers it, so a click in the menu goes through the same path as
 * in the panel - the hook stamps the root element and the storage, and
 * the bar re-renders with the new choice.
 */
function Bar({ trail, who }: { trail: Trail; who: Whoami | undefined }) {
  const { scale, setScale } = useScale();
  return (
    <Topbar
      trail={trail}
      user={who}
      collapsed={false}
      onToggleCollapsed={() => {}}
      onOpenDrawer={() => {}}
      onSignOut={() => {}}
      theme="mocha-peach"
      setTheme={() => {}}
      scale={scale}
      setScale={setScale}
    />
  );
}

function draw(props: { trail?: Trail; who?: Whoami | undefined } = {}) {
  // An explicit `who: undefined` means nobody is signed in; a call without
  // the key means the usual person. A default parameter cannot tell the
  // two apart, so the decision is made here.
  const who = "who" in props ? props.who : user;
  return render(<MemoryRouter><Bar trail={props.trail ?? { section: "Dashboard" }} who={who} /></MemoryRouter>);
}

function openMenu() {
  fireEvent.click(screen.getByRole("button", { name: "Account menu" }));
  return screen.getByRole("dialog", { name: "Account menu" });
}

beforeEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.scale;
});

afterEach(cleanup);

describe("the text size switch", () => {
  it("offers every size the stylesheet knows, with the current one pressed", () => {
    draw();
    const sizes = within(openMenu()).getByRole("group", { name: "Text size" });
    const buttons = within(sizes).getAllByRole("button");
    expect(buttons.map((button) => button.textContent)).toEqual(SCALES.map((entry) => entry.label));
    expect(buttons.map((button) => button.getAttribute("aria-pressed"))).toEqual(["false", "true", "false", "false"]);
    expect(document.documentElement.dataset.scale).toBe("normal");
  });

  it("cycles through the sizes upwards and back, stamping each on the root element and remembering it", () => {
    draw();
    const sizes = within(openMenu()).getByRole("group", { name: "Text size" });
    const press = (label: string) => fireEvent.click(within(sizes).getByRole("button", { name: label }));
    const pressed = () => within(sizes).getAllByRole("button").filter((button) => button.getAttribute("aria-pressed") === "true").map((button) => button.textContent);

    const up: Scale[] = ["large", "larger"];
    for (const code of up) {
      const entry = SCALES.find((item) => item.code === code)!;
      press(entry.label);
      expect(document.documentElement.dataset.scale).toBe(code);
      expect(window.localStorage.getItem(KEY)).toBe(code);
      expect(pressed()).toEqual([entry.label]);
    }
    // Back down, past the default, to the smallest.
    for (const code of ["large", "normal", "small"] as Scale[]) {
      const entry = SCALES.find((item) => item.code === code)!;
      press(entry.label);
      expect(document.documentElement.dataset.scale).toBe(code);
      expect(window.localStorage.getItem(KEY)).toBe(code);
      expect(pressed()).toEqual([entry.label]);
    }
    // The largest and the smallest stay where they are: there is nothing
    // beyond them to cycle to, and a second press changes nothing.
    press("A-");
    expect(document.documentElement.dataset.scale).toBe("small");
    expect(pressed()).toEqual(["A-"]);
  });

  it("starts from the remembered size and keeps the menu open while switching", () => {
    window.localStorage.setItem(KEY, "large");
    draw();
    const menu = openMenu();
    const sizes = within(menu).getByRole("group", { name: "Text size" });
    expect(within(sizes).getByRole("button", { name: "A+" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(within(sizes).getByRole("button", { name: "A++" }));
    expect(screen.getByRole("dialog", { name: "Account menu" })).toBeInTheDocument();
    expect(document.documentElement.dataset.scale).toBe("larger");
  });

  it("explains every size on hover", () => {
    draw();
    const sizes = within(openMenu()).getByRole("group", { name: "Text size" });
    for (const entry of SCALES) {
      expect(within(sizes).getByRole("button", { name: entry.label })).toHaveAttribute("title", entry.description);
    }
  });
});

describe("the account menu", () => {
  it("names the person, the subject behind the display name and the roles", () => {
    draw();
    const trigger = screen.getByRole("button", { name: "Account menu" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(trigger).toHaveAttribute("aria-haspopup", "dialog");
    const menu = openMenu();
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(menu.querySelector(".user-menu-name")).toHaveTextContent("Alice");
    expect(menu.querySelector(".user-menu-subject")).toHaveTextContent("alice@example.org");
    expect(menu.querySelector(".user-menu-roles")).toHaveTextContent("operator");
    expect(within(menu).getByRole("group", { name: "Theme" })).toBeInTheDocument();
    expect(within(menu).getByRole("group", { name: "Language" })).toBeInTheDocument();
  });

  it("says so when the person has no roles and shows a question mark for nobody", () => {
    draw({ who: { ...user, display_name: undefined, roles: [] } });
    const menu = openMenu();
    expect(menu.querySelector(".user-menu-name")).toHaveTextContent("alice@example.org");
    expect(menu.querySelector(".user-menu-subject")).toBeNull();
    expect(menu.querySelector(".user-menu-roles")).toHaveTextContent("no roles");
    cleanup();
    draw({ who: undefined });
    expect(screen.getByRole("button", { name: "Account menu" }).querySelector(".topbar-avatar")).toHaveTextContent("?");
  });

  it("closes on Escape and on a click outside, and stays open on a click inside", () => {
    draw();
    const menu = openMenu();
    fireEvent.mouseDown(within(menu).getByRole("group", { name: "Text size" }));
    expect(screen.getByRole("dialog", { name: "Account menu" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Account menu" })).toBeNull();

    openMenu();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("dialog", { name: "Account menu" })).toBeNull();
  });
});

describe("the trail", () => {
  it("names the section as the current place when the page is the section itself", () => {
    draw();
    const trail = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(trail).getByRole("heading", { level: 1 })).toHaveTextContent("Dashboard");
    expect(within(trail).queryByRole("link")).toBeNull();
    expect(trail).not.toHaveClass("on-host");
    expect(screen.getByTestId("host-picker")).toBeInTheDocument();
  });

  it("puts the host between the section and the module on a host page", () => {
    draw({ trail: { section: "Hosts", to: "/hosts", host, module: "Services" } });
    const trail = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(trail).toHaveClass("on-host");
    expect(within(trail).getByRole("link", { name: "Hosts" })).toHaveAttribute("href", "/hosts");
    const link = within(trail).getByRole("link", { name: /web-01/ });
    expect(link).toHaveAttribute("href", "/hosts/h1");
    expect(link).toHaveTextContent("10.0.0.5");
    expect(link.querySelector(".dot")).toHaveClass("ok");
    expect(link).not.toHaveClass("current");
    expect(trail.querySelector(".topbar-crumb.current")).toHaveTextContent("Services");
  });

  it("makes the host the current place when no module is open, and says when its address is unknown", () => {
    draw({ trail: { section: "Hosts", to: "/hosts", host: { ...host, management_address: undefined, connection_state: "offline" } } });
    const trail = screen.getByRole("navigation", { name: "Breadcrumb" });
    const link = within(trail).getByRole("link", { name: /web-01/ });
    expect(link).toHaveClass("current");
    expect(link).toHaveTextContent("address unknown");
    expect(link.querySelector(".dot")).toHaveClass("error");
    expect(trail.querySelector(".topbar-crumb.current")).toBeNull();
  });
});
