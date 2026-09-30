import { api } from "./api";
import { absoluteTime } from "./format";
import type { Translate } from "../i18n";

/**
 * The first run, as the server describes it.
 *
 * The checklist from /api/v1/setup is the only description of this flow: the
 * steps, their order and their states are the server's. Every screen that shows
 * the flow reads it from here, so a step added or moved on the server reaches
 * all of them at once and no screen can grow a list of its own again.
 */

export type SetupState = "done" | "undone" | "warning" | "optional";

export type SetupStep = {
  key: string;
  state: SetupState;
  detail: string;
  path: string;
};

export type SetupChecklist = {
  steps: SetupStep[];
  done: number;
  total: number;
  complete: boolean;
  next?: string;
  bootstrap_live: boolean;
};

/** What a test button got back: a verdict with either the answer or a typed reason. */
export type ConnectionTest = {
  ok: boolean;
  reason?: string;
  detail?: string;
  summary?: string;
  elapsed_ms: number;
  provider?: { issuer: string; jwks_url: string; keys: number; at: string };
  connector?: { principal: string; keytab_readable: boolean; last_error?: string };
};

/**
 * The one read of the checklist. The first-run screen and the dashboard card
 * share the key, so they share the cache and cannot disagree about the flow
 * even for the moment between two fetches.
 */
export const setupChecklistQuery = {
  queryKey: ["setup"],
  queryFn: () => api.get<SetupChecklist>("/api/v1/setup"),
};

/**
 * The detail of a step is a sentence from the server, and a moment in it
 * comes in the RFC 3339 shape the server writes.
 */
export function readableDetail(detail: string): string {
  return detail.replace(
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g,
    (stamp) => absoluteTime(stamp) || stamp,
  );
}

/** The key of the first step that is undone; the page highlights it. */
export function firstUndone(steps: Pick<SetupStep, "key" | "state">[]): string | undefined {
  return steps.find((step) => step.state === "undone")?.key;
}

/**
 * The steps that are still work, in the server's order. An undone step is a
 * fault and a warning is something configured that stopped answering; an
 * optional step is an integration this installation has none of, which is a
 * choice and not work, so it is asked for nowhere.
 */
export function remainingSteps(steps: SetupStep[]): SetupStep[] {
  return steps.filter((step) => step.state === "undone" || step.state === "warning");
}

/**
 * Whether this installation signs its operators in with API tokens alone. The
 * server says so by leaving the provider optional; a provider that is configured
 * and does not answer is a warning, and what to do about the bootstrap token
 * differs between the two - there is no provider to sign in through here.
 */
export function tokensAlone(steps: Pick<SetupStep, "key" | "state">[]): boolean {
  return steps.some((step) => step.key === "identity_provider" && step.state === "optional");
}

/** The colour a state is shown in: done is fine, undone is a fault, a warning is a warning. */
export function stepTone(state: SetupState): "ok" | "warn" | "error" | "unknown" {
  switch (state) {
    case "done": return "ok";
    case "warning": return "warn";
    case "undone": return "error";
    default: return "unknown";
  }
}

/**
 * Whether the reader may press the test button of a step.
 */
export function mayAct(permissions: Set<string>, key: string): boolean {
  switch (key) {
    case "identity_provider": return permissions.has("settings.read") || permissions.has("principal.manage");
    case "directory": return permissions.has("identity.read");
    case "group_mapping": return permissions.has("principal.manage");
    default: return false;
  }
}

/**
 * The name of the page a path leads to, as the navigation calls it.
 */
export function pageName(path: string): string {
  const [pathname] = path.split("?");
  if (pathname === "/hosts/new") return "Add host";
  switch (pathname.split("/")[1]) {
    case "settings": return "Settings";
    case "access": return "Access";
    case "directory": return "Directory";
    case "hosts": return "Hosts";
    case "relays": return "Relays";
    case "policies": return "Policies";
    case "monitoring": return "Monitoring";
    case "notifications": return "Notifications";
    default: return "Open";
  }
}

/** The words for each state of a step. */
export function stateLabels(t: Translate): Record<SetupState, string> {
  return { done: t("Done"), undone: t("To do"), warning: t("Warning"), optional: t("Optional") };
}

/**
 * The title and the meaning of every step. The server names the state and the
 * path; the words are the panel's, and they live here so that both the
 * first-run screen and the dashboard card name a step the same. A step the
 * server adds before this table knows it is shown under its key rather than
 * dropped, so a new step is visible before it is named.
 */
export function stepGuide(t: Translate): Record<string, { title: string; meaning: string }> {
  return {
    identity_provider: {
      title: t("Identity provider"),
      meaning: t("Operators sign in through the company's identity provider (Keycloak, Entra, any OpenID Connect issuer), so leaving the company means leaving the panel, and every action in the trail carries a real name. An installation that names none takes API tokens alone, which is a choice and not an unfinished step; one that names a provider it cannot reach is the fault this step reports."),
    },
    group_mapping: {
      title: t("First group mapping"),
      meaning: t("A group in the login token grants nothing by itself: a mapping turns a group into a role in a scope. The first one usually maps the platform team to platform_admin fleet-wide; until it exists nobody who signs in through the provider can do anything. With no provider there is no login token to map and none is needed."),
    },
    bootstrap_token: {
      title: t("Bootstrap token"),
      meaning: t("The token the installation started with is a fleet-wide administrator key lying in a file. It exists to hand the fleet to somebody else - a mapped group, or an API token of your own where there is no provider - and once that administrator can sign in, revoke it and delete the file."),
    },
    directory: {
      title: t("Directory connector"),
      meaning: t("A FreeIPA connector lets the panel read who may log in where, join hosts to the domain and show the access rules next to each host. It is optional: a fleet without a directory is managed the same, without the identity views."),
    },
    advertised_address: {
      title: t("Address the agents dial"),
      meaning: t("Every host comes back to one name, and that name is what the panel's own certificate is issued for. The panel offers the addresses it finds on this machine, but it adopts none of them: it cannot tell which of them the hosts route to, and the wrong one enrols a fleet that drops out again."),
    },
    hosts: {
      title: t("First host"),
      meaning: t("A host joins the fleet by running the one-line installation printed on the add-host screen: it gets an agent, a certificate from the fleet CA and a place in a site and an environment. Everything else on this list works on the hosts that are in."),
    },
    relay: {
      title: t("Relay"),
      meaning: t("A relay stands in a site whose hosts cannot reach the panel directly - a branch office, a segmented network - and carries the traffic for them. A fleet on one network needs none."),
    },
    policy: {
      title: t("First policy"),
      meaning: t("A policy declares what is to be true on a set of hosts - a package present, a service running, a file with given content - and the panel keeps judging the hosts against it. Without one the panel reports the hosts as they are and calls nothing a drift."),
    },
    alert_rule: {
      title: t("First alert rule"),
      meaning: t("The agents sample CPU, memory, disks and reachability; an alert rule turns a threshold into an alert on the dashboard. Without one the samples are drawn and nothing is raised."),
    },
    notification_channel: {
      title: t("Notification channel"),
      meaning: t("A channel carries an alert out of the panel - to a chat, a pager or a mailbox - so it reaches somebody who is not looking at the dashboard. Optional: the alerts stand in the panel either way."),
    },
    fleet_ca: {
      title: t("Fleet CA"),
      meaning: t("Every agent certificate is signed by the fleet CA and is trusted by nothing else. A CA near its end needs the next one prepared a month ahead, so every agent renews under it before the old one runs out."),
    },
  };
}
