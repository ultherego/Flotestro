import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { absoluteTime } from "../../lib/format";
import { useCapabilities } from "../../lib/capabilities";
import type { GroupMapping, InstallationProfile, Whoami } from "../../lib/types";
import {
  firstUndone, mayAct, pageName, readableDetail, setupChecklistQuery, stateLabels, stepGuide,
  stepTone, tokensAlone, type ConnectionTest,
} from "../../lib/setup";
import { useToast } from "../../components/Toast";
import { useT } from "../../i18n";
import {
  Actions, Banner, Bones, Button, Card, Fact, Facts, Field, Fields, Form, Meter, Note, Pill,
  Problem, Readout, Screen, Stack, Table,
} from "../kit";
import {
  candidateNote, chosenAddress, confirmable, sourceTone, OWN_ADDRESS,
  type AdvertisedAddressState,
} from "./Settings";

/**
 * The first run: what the panel needs before a company fleet is run from
 * it, what is already there, and where the rest is put in.
 *
 * It is the second screen anybody ever sees, so it is written as
 * instructions and not as a settings page. The steps, their order and
 * their states are the server's - `/api/v1/setup` through `lib/setup`,
 * which is also what the dashboard's card reads - so a step added on the
 * server appears here without this file knowing it exists.
 *
 * Nothing that signs anybody in is drawn here. The bootstrap token is
 * named as live or not; its value lives in a file on the control plane
 * and reaches no screen, no address and no console.
 */

/** The roles a first mapping may grant. */
const ROLES = ["viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin"];

/** How short a reason the audit trail will take for a change of access. */
export const SETUP_REASON_MIN_LENGTH = 8;

/**
 * Where a step of the checklist leads inside the new panel.
 *
 * The server answers with the address of the old panel, which is the one
 * it has always answered with; every link out of a new screen is a new
 * screen, so the prefix is put on here rather than asked of the server.
 */
export function stepLink(path: string): string {
  return path;
}

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

  const list = checklist.data;
  const current = list ? firstUndone(list.steps) : undefined;
  // The words for every step and every state. The server names the state
  // and the path; the words are shared with the dashboard card so one
  // step is named one way wherever it is read.
  const guide = stepGuide(t);
  const stateLabel = stateLabels(t);

  const frame = (children: ReactNode, banner?: ReactNode) => (
    <Screen
      icon="settings"
      title={t("First run")}
      lead={t("What the panel needs before a fleet is run from it.")}
      help={
        <p>
          {t("Work down this list once, in order. Each step says what it is for, what the panel found, and where it is put in; an installation is usable the moment the required ones are done. A step marked optional is an integration this installation has none of — that is a choice, not unfinished work. The bootstrap token the panel started with is a fleet-wide key lying in a file: it exists only to hand the fleet to a real administrator, and this screen never shows it.")}
        </p>
      }
      banner={banner}
    >
      {children}
    </Screen>
  );

  if (checklist.error) return frame(<Problem>{String(checklist.error)}</Problem>);
  if (!list) return frame(<Card title={t("Reading the checklist")}><Bones rows={6} height={18} /></Card>);

  const banner = list.bootstrap_live ? (
    <Banner tone="warn">
      {tokensAlone(list.steps)
        ? t("The bootstrap token still works, and nothing else administers this installation: issue an API token of your own, sign in with it, then revoke this one.")
        : t("The bootstrap token still works. It is for the first mapping only: once an administrator signs in through the provider, revoke it.")}
    </Banner>
  ) : undefined;

  /*
   * What can be done from this screen, under its own heading.
   *
   * Four of the steps are finished here rather than elsewhere - two
   * connection tests, the address the fleet dials and the first mapping -
   * and each is a decision, so each stands on a face of its own with the
   * step's own meaning over it. The rest of the list is a reading, and a
   * reading is a row.
   */
  const decisions = list.steps.flatMap((step) => {
    const words = guide[step.key] ?? { title: step.key, meaning: "" };
    if (step.key === "identity_provider" && capabilities.identity_provider && mayAct(permissions, step.key)) {
      return [(
        <Form key={step.key} title={words.title} note={t("Ask the provider now; what it answers is what this step reports.")}>
          <ConnectionTester
            path="/api/v1/setup/test-oidc"
            label={t("Test the identity provider")}
            testId="test-oidc"
          />
        </Form>
      )];
    }
    if (step.key === "directory" && capabilities.directory && mayAct(permissions, step.key)) {
      return [(
        <Form key={step.key} title={words.title} note={t("Ask the directory now; what it answers is what this step reports.")}>
          <ConnectionTester
            path="/api/v1/setup/test-directory"
            label={t("Test the directory")}
            testId="test-directory"
          />
        </Form>
      )];
    }
    if (step.key === "advertised_address") {
      return [(
        <Form key={step.key} title={words.title} note={words.meaning}>
          <AdvertisedAddressStep mayConfirm={permissions.has("settings.advertise.write")} />
        </Form>
      )];
    }
    if (step.key === "group_mapping") {
      return [(
        <Form key={step.key} title={words.title} note={words.meaning}>
          {mayAct(permissions, step.key)
            ? <MappingForm open={step.state === "undone"} />
            : <Note>{t("Only whoever manages access can add a mapping; ask an administrator.")}</Note>}
        </Form>
      )];
    }
    return [];
  });

  return frame(
    <>
      <Card
        title={list.complete
          ? t("Every required step is done")
          : t("{done} of {total} required steps done", { done: list.done, total: list.total })}
        note={list.complete
          ? t("The warnings and the optional steps below are advice, not blockers.")
          : t("The first step left is marked; the optional ones can wait.")}
      >
        <Meter
          share={list.done / Math.max(list.total, 1)}
          tone={list.complete ? "ok" : "info"}
          text={t("{done} of {total}", { done: list.done, total: list.total })}
        />
      </Card>

      {/* Twelve steps were twelve cards until 17.10, and the list could
          not be read in one glance: a step is a row, its state is a word
          in it, and what the panel found is the line beside it. */}
      <Card
        title={t("The steps")}
        note={t("In the order the work is done. What each step is for is under its name; the ones finished on this screen are below the list.")}
        flush
      >
        <Table
          rows={list.steps.map((step, index) => ({ step, index }))}
          keyOf={(one) => one.step.key}
          rowTestId={(one) => `step-${one.step.key}`}
          testId="setup-steps"
          empty={t("This installation reports no steps.")}
          columns={[
            {
              key: "step",
              head: t("Step"),
              cell: ({ step, index }) => {
                const words = guide[step.key] ?? { title: step.key, meaning: "" };
                return (
                  <span title={words.meaning}>
                    {`${index + 1}. ${words.title}`}
                    {step.key === current && <> <Pill tone="warn">{t("do this next")}</Pill></>}
                  </span>
                );
              },
            },
            {
              key: "state",
              head: t("State"),
              cell: ({ step }) => <Pill tone={stepTone(step.state)}>{stateLabel[step.state]}</Pill>,
            },
            {
              key: "found",
              head: t("What the panel found"),
              cell: ({ step }) => <span data-testid={`found-${step.key}`}>{readableDetail(step.detail)}</span>,
            },
            {
              key: "where",
              head: t("Where"),
              tight: true,
              actions: true,
              cell: ({ step }) => (
                step.path !== "/setup"
                  ? <Link to={stepLink(step.path)} data-testid={`go-${step.key}`}>{t(pageName(step.path))}</Link>
                  : <span className="fl-faint">{t("here")}</span>
              ),
            },
          ]}
        />
      </Card>

      {decisions.length > 0 && <Stack wide>{decisions}</Stack>}
    </>,
    banner,
  );
}

/** A test button with its verdict beside it. */
function ConnectionTester({ path, label, testId }: { path: string; label: string; testId: string }) {
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
    <Stack>
      <Actions>
        <Button kind="quiet" onClick={() => test.mutate()} disabled={test.isPending} testId={testId}>
          {test.isPending ? t("Testing…") : label}
        </Button>
        {result && (
          <Pill tone={result.ok ? "ok" : "error"}>
            <span data-testid={`${testId}-verdict`}>
              {result.ok ? t("Answered in {ms} ms", { ms: result.elapsed_ms }) : result.reason ?? t("failed")}
            </span>
          </Pill>
        )}
      </Actions>
      {test.error && <Problem>{String(test.error)}</Problem>}
      {result && (
        <Note>
          {result.ok && result.provider && t("Issuer {issuer}, {keys} signing keys at {url}.", {
            issuer: result.provider.issuer, keys: result.provider.keys, url: result.provider.jwks_url,
          })}
          {result.ok && result.connector && (result.summary || t("The directory answered as {principal}.", { principal: result.connector.principal }))}
          {!result.ok && (result.detail ?? "")}
        </Note>
      )}
    </Stack>
  );
}

/** The first mapping, put in without leaving the checklist. */
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
      void queryClient.invalidateQueries({ queryKey: ["setup"] });
      void queryClient.invalidateQueries({ queryKey: ["group-mappings"] });
    },
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  if (!open) {
    return (
      <Actions>
        <Button kind="quiet" onClick={() => setOpen(true)} testId="mapping-open">
          {t("Add a mapping here")}
        </Button>
      </Actions>
    );
  }

  const ready = group.trim() !== "" && reason.trim().length >= SETUP_REASON_MIN_LENGTH;
  return (
    <Stack>
      <StepUpWarning error={warning} close={() => setWarning(null)} />
      <Fields>
        <Field label={t("Identity provider group")} hint={t("The group name as it appears in the login token.")}>
          <input value={group} onChange={(event) => setGroup(event.target.value)} placeholder="flotestro-admins"
                 data-testid="mapping-group" />
        </Field>
        <Field label={t("Role")}>
          <select value={role} onChange={(event) => setRole(event.target.value)} data-testid="mapping-role">
            {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </Field>
        <Field label={t("Site (empty = all)")}>
          <input value={site} onChange={(event) => setSite(event.target.value)} placeholder="lab"
                 data-testid="mapping-site" />
        </Field>
        <Field label={t("Environment (empty = all)")}>
          <input value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="test"
                 data-testid="mapping-environment" />
        </Field>
        <Field
          label={t("Reason for the change")}
          hint={t("At least {n} characters; the button opens when they are there.", { n: SETUP_REASON_MIN_LENGTH })}
          wide
        >
          <input value={reason} onChange={(event) => setReason(event.target.value)}
                 placeholder={t("e.g. first run: the platform team administers the fleet")}
                 data-testid="mapping-reason" />
        </Field>
      </Fields>
      <Actions>
        <Button disabled={!ready || add.isPending} onClick={() => add.mutate()} testId="mapping-add">
          {add.isPending ? t("Working…") : t("Add mapping")}
        </Button>
        <Button kind="quiet" onClick={() => setOpen(false)} disabled={add.isPending} testId="mapping-cancel">
          {t("Cancel")}
        </Button>
      </Actions>
    </Stack>
  );
}

/** The refusal of a change to the access rules. */
function StepUpWarning({ error, close }: { error: ApiError | null; close: () => void }) {
  const t = useT();
  if (!error) return null;
  if (error.code === "reauthentication_required") {
    return (
      <Banner
        tone="warn"
        actions={
          <>
            <Button
              onClick={() => {
                const target = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = `/auth/login?step_up=1&redirect=${target}`;
              }}
              testId="step-up"
            >
              {t("Sign in again")}
            </Button>
            <Button kind="quiet" onClick={close}>{t("Close")}</Button>
          </>
        }
      >
        <b>{t("Re-authentication required.")}</b> {error.message}
      </Banner>
    );
  }
  return (
    <Banner tone="error" actions={<Button kind="quiet" onClick={close}>{t("Close")}</Button>}>
      {error.message}
    </Banner>
  );
}

/**
 * The address the agents dial, inside the step that asks for it.
 *
 * The panel cannot tell which of its own interfaces the hosts route to,
 * and the wrong one in the certificate is a fleet that enrols and drops
 * out again, so a detected address stays a proposal until somebody says
 * otherwise. The step card carries the title and the meaning; this is the
 * state, the proposals and the confirmation.
 */
function AdvertisedAddressStep({ mayConfirm }: { mayConfirm: boolean }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [picked, setPicked] = useState("");
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [refusal, setRefusal] = useState<ApiError | null>(null);

  const address = useQuery({
    queryKey: ["advertised-address"],
    queryFn: () => api.get<AdvertisedAddressState>("/api/v1/settings/advertised"),
    retry: false,
  });

  const confirm = useMutation({
    mutationFn: (names: string[]) =>
      api.put<AdvertisedAddressState>("/api/v1/settings/advertised", { names, reason: reason.trim() }),
    onSuccess: (state) => {
      setRefusal(null);
      toast.success(t("The agents now dial {names}.", { names: state.in_force.join(", ") }));
      void queryClient.invalidateQueries({ queryKey: ["advertised-address"] });
      void queryClient.invalidateQueries({ queryKey: ["setup"] });
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      void queryClient.invalidateQueries({ queryKey: ["installation-profile"] });
    },
    onError: (error) => setRefusal(error instanceof ApiError ? error : null),
  });

  if (address.error) return <Problem>{String(address.error)}</Problem>;
  const state = address.data;
  if (!state) return <Bones rows={3} />;
  // An answer without the address in force is not an address of none: it
  // is an answer this section cannot read, and it says so rather than
  // taking the whole checklist down with it.
  if (!Array.isArray(state.in_force)) {
    return (
      <Note>
        <span data-testid="advertised-address">{t("This panel did not say which address is in force.")}</span>
      </Note>
    );
  }

  const names = chosenAddress(picked, typed);
  const ready = confirmable(names, state.environment_in_force);

  return (
    <Stack>
      <Facts>
        <Fact label={t("In force")}>
          <span className="fl-mono" data-testid="advertised-address">{state.in_force.join(", ")}</span>{" "}
          <Pill tone={sourceTone(state.source, state.loopback_only)}>
            {state.source === "environment" && t("declared in the deployment")}
            {state.source === "confirmed" && t("confirmed")}
            {state.source === "default" && t("not confirmed")}
          </Pill>
        </Fact>
        {state.source === "confirmed" && state.confirmed_by && (
          <Fact label={t("Confirmed by")}>
            {t("{who} on {when}", {
              who: state.confirmed_by,
              when: absoluteTime(state.confirmed_at ?? "") || (state.confirmed_at ?? ""),
            })}
          </Fact>
        )}
      </Facts>

      {state.loopback_only && (
        <Note>{t("This reaches only the machine the panel runs on, so a host elsewhere is turned away at enrolment rather than left to fail a handshake later.")}</Note>
      )}
      {state.mismatch && <Banner tone="warn">{state.mismatch}</Banner>}
      {state.superseded && state.superseded.length > 0 && (
        <Note>
          {t("Held back from any relay as well, because an agent not yet reconfigured still dials it: {names}.", {
            names: state.superseded.join(", "),
          })}
        </Note>
      )}

      {state.environment_in_force ? (
        <Note>
          {t("This installation declares the address in the environment of the control plane ({names}), and that declaration decides. Change it there; a confirmation made here would be refused rather than kept where it does not take effect.", {
            names: (state.environment ?? []).join(", "),
          })}
        </Note>
      ) : !mayConfirm ? (
        <Note>{t("Only a platform administrator names the address the fleet connects to; ask one.")}</Note>
      ) : (
        <>
          <Note>{t("The panel read these off its own interfaces. It cannot tell which of them the hosts route to, so none of them is in use until you pick one and confirm it.")}</Note>
          <Fields>
            {state.candidates.map((candidate) => (
              <Field key={`${candidate.kind}:${candidate.name}`} label={candidate.name} hint={candidateNote(candidate, t)}>
                <input
                  type="radio"
                  name="advertised-candidate"
                  value={candidate.name}
                  checked={picked === candidate.name}
                  onChange={() => setPicked(candidate.name)}
                  data-testid={`advertised-${candidate.name}`}
                />
              </Field>
            ))}
            <Field
              label={t("a name of your own")}
              hint={t("The DNS name the hosts resolve, which is usually not an address of an interface. Several, separated by commas, are tried in order.")}
            >
              <input
                type="radio"
                name="advertised-candidate"
                value={OWN_ADDRESS}
                checked={picked === OWN_ADDRESS}
                onChange={() => setPicked(OWN_ADDRESS)}
                data-testid="advertised-own"
              />
            </Field>
            <Field label={t("The name the hosts resolve")} wide>
              <input
                value={typed}
                placeholder="panel.example.org"
                disabled={picked !== OWN_ADDRESS}
                onChange={(event) => setTyped(event.target.value)}
                data-testid="advertised-typed"
              />
            </Field>
            <Field label={t("Reason")} hint={t("Kept on the audit trail beside the names. Optional.")} wide>
              <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="advertised-reason" />
            </Field>
          </Fields>
          {refusal && (
            <Problem>
              <span data-testid="advertised-refusal">
                {refusal.code === "advertised_address_from_environment"
                  ? t("The deployment declares the address, so it is not confirmed here.")
                  : refusal.message}
              </span>
            </Problem>
          )}
          <Actions>
            <Button
              disabled={!ready || confirm.isPending}
              onClick={() => confirm.mutate(names)}
              testId="advertised-confirm"
            >
              {confirm.isPending
                ? t("Confirming…")
                : names.length > 0
                  ? t("Confirm {names}", { names: names.join(", ") })
                  : t("Confirm the address")}
            </Button>
          </Actions>
          <Note>{state.note}</Note>
        </>
      )}

      {/* What was just confirmed decides this, not the query: the answer to
          the confirmation is the newest word on the address, and the read
          behind it may still be in flight. */}
      {confirm.data && !confirm.data.loopback_only && <AgentConfiguration />}
    </Stack>
  );
}

/**
 * What a new host is told, now that the address is settled. It is read
 * from the installation profile rather than composed here: that is the
 * same file the operator pastes onto a host, so a screen that rebuilt it
 * could agree with nothing.
 */
function AgentConfiguration() {
  const t = useT();
  const profile = useQuery({
    queryKey: ["installation-profile", "advertised-address"],
    queryFn: () => api.get<InstallationProfile>("/api/v1/installation-profiles?kind=agent"),
    retry: false,
  });
  if (profile.error) return <Problem>{String(profile.error)}</Problem>;
  const data = profile.data;
  if (!data) return <Bones rows={2} />;
  return (
    <Stack>
      <Readout
        label={t("The agent configuration that now applies")}
        value={data.config.content}
        note={t("This is what the add-host screen hands out from now on; it is written to {path} on the host.", {
          path: data.config.path,
        })}
        lines={12}
        testId="advertised-agent-config"
      />
      {(data.warnings ?? []).map((warning) => <Note key={warning}>{warning}</Note>)}
    </Stack>
  );
}
