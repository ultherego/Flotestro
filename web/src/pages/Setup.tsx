import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import type { GroupMapping, Whoami } from "../lib/types";
import { useCapabilities } from "../lib/capabilities";
import { ErrorBox, Empty } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { Meter } from "../components/widgets";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The first run. A fresh panel has a bootstrap token, an empty fleet and
 * no rule that says who may sign in; the operator would otherwise learn
 * what is missing one refusal at a time. The checklist comes from the
 * server - it counts what is there - and the page adds what each step
 * means for a company fleet, the page each is done on, and the two forms
 * that need no page of their own.
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

const ROLES = ["viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin"];

/** The reason every change of the access rules is recorded with. */
const REASON_MIN_LENGTH = 8;

/** The key of the first step that is undone; the page highlights it. */
export function firstUndone(steps: Pick<SetupStep, "key" | "state">[]): string | undefined {
  return steps.find((step) => step.state === "undone")?.key;
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
 * Whether the reader may press the test button of a step. The identity
 * provider test reveals the issuer and its keys, so it is for whoever
 * reads the settings; the directory test is for whoever reads the
 * identity views it decides the fate of; the mapping form is for whoever
 * manages access.
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
 * The name of the page a path leads to, as the navigation calls it. The
 * server sends the path; the button beside a step is named after where
 * it goes, and a step done on the hosts list is not "Add host".
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

export function Setup() {
  const t = useT();
  const capabilities = useCapabilities();
  const checklist = useQuery({
    queryKey: ["setup"],
    queryFn: () => api.get<SetupChecklist>("/api/v1/setup"),
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: Infinity,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);

  if (checklist.error) return <ErrorBox error={checklist.error} />;
  const list = checklist.data;
  const current = list ? firstUndone(list.steps) : undefined;

  // The title, the meaning and the name of the page of every step. The
  // server names the state and the path; the words are the panel's.
  const guide: Record<string, { title: string; meaning: string }> = {
    identity_provider: {
      title: t("Identity provider"),
      meaning: t("Operators sign in through the company's identity provider (Keycloak, Entra, any OpenID Connect issuer), so leaving the company means leaving the panel, and every action in the trail carries a real name. Without it the panel takes API tokens alone."),
    },
    group_mapping: {
      title: t("First group mapping"),
      meaning: t("A group in the login token grants nothing by itself: a mapping turns a group into a role in a scope. The first one usually maps the platform team to platform_admin fleet-wide; until it exists nobody who signs in can do anything."),
    },
    bootstrap_token: {
      title: t("Bootstrap token"),
      meaning: t("The token the installation started with is a fleet-wide administrator key lying in a file. It exists to create the first mapping; once the mapped administrators can sign in, revoke it and delete the file."),
    },
    directory: {
      title: t("Directory connector"),
      meaning: t("A FreeIPA connector lets the panel read who may log in where, join hosts to the domain and show the access rules next to each host. It is optional: a fleet without a directory is managed the same, without the identity views."),
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

  const stateLabel: Record<SetupState, string> = {
    done: t("Done"), undone: t("To do"), warning: t("Warning"), optional: t("Optional"),
  };

  return (
    <>
      <PageHeader
        title={t("First run")}
        description={t("What the panel needs before a company fleet is run from it, what is already there, and where the rest is put in.")}
        icon="settings"
      />

      {!list ? <Card><Empty>{t("Loading…")}</Empty></Card> : (
        <div className="stack">
          <Card
            title={list.complete ? t("Every required step is done") : t("{done} of {total} required steps done", { done: list.done, total: list.total })}
            description={list.complete
              ? t("The warnings and the optional steps below are advice, not blockers.")
              : t("The first step left is highlighted; the optional ones can wait.")}
          >
            <Meter value={list.done} max={Math.max(list.total, 1)} tone={list.complete ? "ok" : "info"} />
            {list.bootstrap_live && (
              <p className="source" style={{ marginTop: 10 }}>
                {t("The bootstrap token still works. It is for the first mapping only: once an administrator signs in through the provider, revoke it.")}
              </p>
            )}
          </Card>

          {list.steps.map((step, index) => {
            const words = guide[step.key] ?? { title: step.key, meaning: "" };
            const isCurrent = step.key === current;
            return (
              <Card
                key={step.key}
                tone={isCurrent ? "warn" : undefined}
                title={<>{index + 1}. {words.title} <span className={`badge ${stepTone(step.state)}`}>{stateLabel[step.state]}</span></>}
                description={words.meaning}
                actions={step.path !== "/setup" && (
                  <Link className="button" to={step.path}>{t(pageName(step.path))}</Link>
                )}
              >
                <p style={{ margin: 0 }}>
                  <strong>{t("Found:")}</strong> {step.detail}
                </p>
                {step.key === "identity_provider" && capabilities.identity_provider && mayAct(permissions, step.key) && (
                  <ConnectionTester path="/api/v1/setup/test-oidc" label={t("Test the identity provider")} />
                )}
                {step.key === "directory" && capabilities.directory && mayAct(permissions, step.key) && (
                  <ConnectionTester path="/api/v1/setup/test-directory" label={t("Test the directory")} />
                )}
                {step.key === "group_mapping" && (
                  mayAct(permissions, step.key)
                    ? <MappingForm open={step.state === "undone"} />
                    : <p className="source" style={{ marginTop: 10 }}>{t("Only whoever manages access can add a mapping; ask an administrator.")}</p>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </>
  );
}

/**
 * A test button with its verdict beside it. The server answers 200 either
 * way: ok with what the other side said, or a typed reason - a directory
 * that does not answer is a finding, not a failure of the panel.
 */
function ConnectionTester({ path, label }: { path: string; label: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const test = useMutation({
    mutationFn: () => api.post<ConnectionTest>(path),
    // A test that just ran is the freshest word on the step: the
    // checklist is read again so its state agrees with the verdict.
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["setup"] }),
  });
  const result = test.data;
  return (
    <div style={{ marginTop: 12 }}>
      <Actions>
        <button className="secondary" onClick={() => test.mutate()} disabled={test.isPending}>
          {test.isPending ? t("Testing…") : label}
        </button>
        {result && (
          <span className={`badge ${result.ok ? "ok" : "error"}`}>
            {result.ok ? t("Answered in {ms} ms", { ms: result.elapsed_ms }) : result.reason ?? t("failed")}
          </span>
        )}
      </Actions>
      {test.error && <ErrorBox error={test.error} />}
      {result && (
        <p className="source" style={{ marginTop: 8 }}>
          {result.ok && result.provider && t("Issuer {issuer}, {keys} signing keys at {url}.", {
            issuer: result.provider.issuer, keys: result.provider.keys, url: result.provider.jwks_url,
          })}
          {result.ok && result.connector && (result.summary || t("The directory answered as {principal}.", { principal: result.connector.principal }))}
          {!result.ok && (result.detail ?? "")}
        </p>
      )}
    </div>
  );
}

/**
 * The first mapping, in place. The body and the step-up handling are the
 * ones the access screen uses: the same route, the same reason, the same
 * sign-in-again when the server wants a fresh authentication.
 */
function MappingForm({ open: initiallyOpen }: { open: boolean }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(initiallyOpen);
  const [group, setGroup] = useState("");
  const [role, setRole] = useState("platform_admin");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [reason, setReason] = useState("");
  const [warning, setWarning] = useState<ApiError | null>(null);

  const add = useMutation({
    mutationFn: () =>
      api.post<GroupMapping>("/api/v1/group-mappings", {
        group_name: group.trim(), role,
        site: site.trim(), environment: environment.trim(), reason: reason.trim(),
      }),
    onSuccess: (mapping) => {
      setGroup(""); setReason(""); setWarning(null); setOpen(false);
      toast.success(t("The group {group} now grants {role}.", { group: mapping.group_name, role: mapping.role }), {
        link: { to: "/access?tab=mappings", label: t("Group mappings") },
      });
      queryClient.invalidateQueries({ queryKey: ["setup"] });
      queryClient.invalidateQueries({ queryKey: ["group-mappings"] });
    },
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  if (!open) {
    return (
      <div style={{ marginTop: 12 }}>
        <Actions><button className="secondary" onClick={() => setOpen(true)}>{t("Add a mapping here")}</button></Actions>
      </div>
    );
  }
  const ready = group.trim() !== "" && reason.trim().length >= REASON_MIN_LENGTH;
  return (
    <div style={{ marginTop: 12 }}>
      <StepUpWarning error={warning} close={() => setWarning(null)} />
      <FieldGrid>
        <Field label={t("Identity provider group")} hint={t("The group name as it appears in the login token.")}>
          <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="flotestro-admins" />
        </Field>
        <Field label={t("Role")}>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </Field>
        <Field label={t("Site (empty = all)")}>
          <input value={site} onChange={(e) => setSite(e.target.value)} placeholder="lab" />
        </Field>
        <Field label={t("Environment (empty = all)")}>
          <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="test" />
        </Field>
        <Field label={t("Reason for the change")} hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("e.g. first run: the platform team administers the fleet")} />
        </Field>
      </FieldGrid>
      <Actions>
        <button disabled={!ready || add.isPending} onClick={() => add.mutate()}>
          {add.isPending ? t("Working…") : t("Add mapping")}
        </button>
        <button className="secondary" onClick={() => setOpen(false)} disabled={add.isPending}>{t("Cancel")}</button>
      </Actions>
    </div>
  );
}

/**
 * The refusal of a change to the access rules. A demand for a fresh
 * authentication is the one case the page can act on: it offers signing
 * in again and coming back here. Any other refusal is shown as it is.
 */
function StepUpWarning({ error, close }: { error: ApiError | null; close: () => void }) {
  const t = useT();
  if (!error) return null;
  if (error.code === "reauthentication_required") {
    return (
      <div className="warning">
        <div><strong>{t("Re-authentication required.")}</strong> {error.message}</div>
        <div className="operations">
          <button onClick={() => {
            const target = encodeURIComponent(window.location.pathname + window.location.search);
            window.location.href = `/auth/login?step_up=1&redirect=${target}`;
          }}>
            {t("Sign in again")}
          </button>
          <button className="secondary" onClick={close}>{t("Close")}</button>
        </div>
      </div>
    );
  }
  return (
    <div className="warning">
      <div>{error.message}</div>
      <div className="operations"><button onClick={close}>{t("Close")}</button></div>
    </div>
  );
}
