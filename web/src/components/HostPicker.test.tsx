import { describe, expect, it } from "vitest";
import type { Host } from "../lib/types";
import type { Capabilities } from "../lib/capabilities";
import { groupResults, hostPath, matchCommands, navigationCommands, rank, type SearchItem } from "./HostPicker";

/* The palette is a list built from three sources - the server's hits, the
   remembered hosts and the places of the panel - by pure functions; every
   decision about order, gating and destination is checked here without a
   screen or a server. */

const installation: Capabilities = {
  identity_provider: false, directory: false, directory_write: false, local_users: false, campaign_v2: true,
};

describe("navigationCommands", () => {
  it("lists the places every reader has and gates the rest by permission", () => {
    const paths = navigationCommands([], installation).map((command) => command.to);
    expect(paths).toEqual(["/dashboard", "/hosts", "/groups", "/jobs", "/reads"]);
  });

  it("opens a place for its permission, as the sidebar does", () => {
    const paths = navigationCommands(
      ["campaign.read", "policy.read", "secret.read", "audit.read", "host.enroll.create", "host.enroll.read"],
      installation,
    ).map((command) => command.to);
    expect(paths).toContain("/hosts/new");
    expect(paths).toContain("/relays");
    expect(paths).toContain("/bulk");
    expect(paths).toContain("/campaigns");
    expect(paths).toContain("/policies");
    expect(paths).toContain("/secrets");
    expect(paths).toContain("/audit");
    expect(paths).not.toContain("/access");
    expect(paths).not.toContain("/settings");
    expect(paths).not.toContain("/directory");
  });

  it("gives whoever manages access the access and the settings screens, and the directory only with a directory", () => {
    const managing = navigationCommands(["principal.manage"], installation).map((command) => command.to);
    expect(managing).toContain("/access");
    expect(managing).toContain("/settings");
    expect(managing).not.toContain("/directory");
    const withDirectory = navigationCommands([], { ...installation, directory: true }).map((command) => command.to);
    expect(withDirectory).toContain("/directory");
  });
});

describe("rank", () => {
  it("orders a whole match before a beginning, a word before a fragment, and the rest last", () => {
    expect(rank("web-01", "web-01")).toBe(0);
    expect(rank("web-01", "WEB")).toBe(1);
    expect(rank("restart with a budget", "budget")).toBe(2);
    expect(rank("db-primary.lab", "lab")).toBe(2);
    expect(rank("kubernetes", "bern")).toBe(3);
    expect(rank("kubernetes", "mail")).toBe(4);
    expect(rank("anything", "")).toBe(4);
  });
});

describe("groupResults", () => {
  const items: SearchItem[] = [
    { kind: "campaign", id: "c1", title: "web restart", subtitle: "", path: "/campaigns/c1" },
    { kind: "host", id: "h2", title: "webmail", subtitle: "", path: "/hosts/h2/overview" },
    { kind: "host", id: "h1", title: "web", subtitle: "", path: "/hosts/h1/overview" },
    { kind: "host", id: "h3", title: "old-web", subtitle: "", path: "/hosts/h3/overview" },
    { kind: "secret", id: "s1", title: "web-tls", subtitle: "", path: "/secrets/web-tls" },
  ];

  it("keeps the kinds in their order and the best answer first inside a kind", () => {
    const rows = groupResults(items, "web");
    expect(rows.map((row) => row.key)).toEqual(["host:h1", "host:h2", "host:h3", "campaign:c1", "secret:s1"]);
    expect(rows.map((row) => row.group)).toEqual(["Hosts", "Hosts", "Hosts", "Campaigns", "Secrets"]);
  });

  it("keeps the server's order between equal answers", () => {
    const rows = groupResults([
      { kind: "host", id: "b", title: "web-02", subtitle: "", path: "/hosts/b/overview" },
      { kind: "host", id: "a", title: "web-01", subtitle: "", path: "/hosts/a/overview" },
    ], "web");
    expect(rows.map((row) => row.key)).toEqual(["host:b", "host:a"]);
  });

  it("marks a host row by its identifier so the star and the module switch find it, and nothing else", () => {
    const rows = groupResults(items, "web");
    expect(rows.find((row) => row.key === "host:h1")?.hostID).toBe("h1");
    expect(rows.find((row) => row.key === "campaign:c1")?.hostID).toBeUndefined();
    expect(rows.every((row) => !row.command)).toBe(true);
  });

  it("carries the icon of the kind and the path the server gave", () => {
    const rows = groupResults(items, "web");
    expect(rows.find((row) => row.key === "secret:s1")).toMatchObject({ icon: "secrets", path: "/secrets/web-tls" });
    expect(rows.find((row) => row.key === "campaign:c1")).toMatchObject({ icon: "campaigns", path: "/campaigns/c1" });
  });

  it("leaves out a kind this build does not know", () => {
    const rows = groupResults([{ kind: "planet" as SearchItem["kind"], id: "p", title: "mars", subtitle: "", path: "/mars" }], "ma");
    expect(rows).toEqual([]);
  });
});

describe("matchCommands", () => {
  const commands = navigationCommands(["audit.read", "principal.manage", "host.enroll.create"], installation);
  const polish: Record<string, string> = { Audit: "Dziennik", Access: "Dostęp", Hosts: "Hosty" };
  const translate = (label: string) => polish[label] ?? label;

  it("keeps every command for an empty query, under the heading of the places", () => {
    const rows = matchCommands(commands, "", translate);
    expect(rows.length).toBe(commands.length);
    expect(rows.every((row) => row.group === "Go to" && row.command)).toBe(true);
  });

  it("matches the label in either language and leads to the place", () => {
    expect(matchCommands(commands, "aud", translate).map((row) => row.path)).toEqual(["/audit"]);
    expect(matchCommands(commands, "dzien", translate).map((row) => row.path)).toEqual(["/audit"]);
    expect(matchCommands(commands, "hosty", translate).map((row) => row.path)).toEqual(["/hosts"]);
  });

  it("puts the better answer first", () => {
    const paths = matchCommands(commands, "host", translate).map((row) => row.path);
    expect(paths[0]).toBe("/hosts");
    expect(paths).toContain("/hosts/new");
  });

  it("drops the commands the query does not name", () => {
    expect(matchCommands(commands, "zzz", translate)).toEqual([]);
  });
});

describe("hostPath", () => {
  const docker = { id: "h1", hostname: "app-01", capabilities: [{ name: "docker", available: true }] } as unknown as Host;
  const bare = { id: "h2", hostname: "db-01", capabilities: [{ name: "docker", available: false, reason: "docker is not installed" }] } as unknown as Host;

  it("leads to the overview when no module is open", () => {
    expect(hostPath({ id: "h1", host: docker }, "", installation)).toEqual({ path: "/hosts/h1/overview" });
  });

  it("keeps the open module on a host that supports it", () => {
    expect(hostPath({ id: "h1", host: docker }, "containers", installation)).toEqual({ path: "/hosts/h1/containers" });
  });

  it("falls back to the overview with the reason when the host lacks the module", () => {
    expect(hostPath({ id: "h2", host: bare }, "containers", installation)).toEqual({
      path: "/hosts/h2/overview",
      state: { rejected: "Containers", reason: "docker is not installed" },
    });
  });

  it("keeps the module for a host it has no record of; the workspace judges there", () => {
    expect(hostPath({ id: "h3" }, "containers", installation)).toEqual({ path: "/hosts/h3/containers" });
  });
});
