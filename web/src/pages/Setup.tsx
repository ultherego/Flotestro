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
import {
  firstUndone, mayAct, pageName, readableDetail, setupChecklistQuery, stateLabels, stepGuide,
  stepTone, tokensAlone, type ConnectionTest,
} from "../lib/setup";
import { useT } from "../i18n";
import { AdvertisedAddressSection } from "./AdvertisedAddress";

/**
 * The first run. The steps, their order and their states come from the server's
 * checklist in lib/setup, which is also what the dashboard card reads.
 */

const ROLES = ["viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin"];

/** The reason every change of the access rules is recorded with. */
const REASON_MIN_LENGTH = 8;

export function Setup() {
  const t = useT();
  const capabilities = useCapabilities();
  const checklist = useQuery(setupChecklistQuery);
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: Infinity,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);

  if (checklist.error) return <ErrorBox error={checklist.error} />;
  const list = checklist.data;
  const current = list ? firstUndone(list.steps) : undefined;

  // The words for every step and every state. The server names the state and
  // the path; the words are shared with the dashboard card so one step is
  // named one way.
  const guide = stepGuide(t);
  const stateLabel = stateLabels(t);

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
            <Meter
              value={list.done}
              max={Math.max(list.total, 1)}
              tone={list.complete ? "ok" : "info"}
              text={t("{done} of {total}", { done: list.done, total: list.total })}
            />
            {list.bootstrap_live && (
              <p className="source" style={{ marginTop: 10 }}>
                {tokensAlone(list.steps)
                  ? t("The bootstrap token still works, and nothing else administers this installation: issue an API token of your own, sign in with it, then revoke this one.")
                  : t("The bootstrap token still works. It is for the first mapping only: once an administrator signs in through the provider, revoke it.")}
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
                  <strong>{t("Found:")}</strong> {readableDetail(step.detail)}
                </p>
                {step.key === "identity_provider" && capabilities.identity_provider && mayAct(permissions, step.key) && (
                  <ConnectionTester path="/api/v1/setup/test-oidc" label={t("Test the identity provider")} />
                )}
                {step.key === "directory" && capabilities.directory && mayAct(permissions, step.key) && (
                  <ConnectionTester path="/api/v1/setup/test-directory" label={t("Test the directory")} />
                )}
                {step.key === "advertised_address" && (
                  <AdvertisedAddressSection mayConfirm={permissions.has("settings.advertise.write")} />
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
 * A test button with its verdict beside it.
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
 * The first mapping, in place.
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
 * The refusal of a change to the access rules.
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
