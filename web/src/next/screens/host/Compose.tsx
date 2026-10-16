import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../../../lib/api";
import { useModuleAccess, useAllowed } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import { stateName } from "../../../components/ui";
import type { Host, Job } from "../../../lib/types";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Bars, Button, Card, Empty, Field, Fields, Note, Pill, Problem,
  Readout, Stack, Table, type Segment, type Tone,
  stacked,
} from "../../kit";

/**
 * The Compose projects of one machine: a manifest is the desired state, so
 * it is planned first and then deployed exactly as planned.
 *
 * Two things are load-bearing and neither is appearance. The deployment
 * carries the digest of the plan and the digest of every image in it, so a
 * tag that moved between the plan and the consent makes the host refuse
 * rather than start something nobody approved. And a count nobody took -
 * no project named, no plan computed - is an em dash here, never a nought.
 */

type ProjectVersion = {
  job_id: string;
  state: string;
  plan_digest?: string;
  manifest: string;
  created_by: string;
  created_at: string;
  applied: boolean;
};

type PlanService = {
  name: string;
  image: string;
  /** The digest the tag resolved to when the plan was computed: what the deployment binds. */
  image_digest?: string;
  /** Where the digest came from: reference, registry or local. */
  digest_source?: string;
  /** The reference the containers are started from: the repository with the digest. */
  pinned_image?: string;
  replicas?: number;
};

type PlanChange = { kind: string; name: string; action: string };

export type ProjectPlan = {
  project: string;
  digest: string;
  services?: PlanService[];
  changes?: PlanChange[];
  warnings?: string[];
};

/** The changes this module offers; when every one is refused, it says so once. */
const COMPOSE_CHANGES = ["docker.compose.deploy"];

/** How long the screen waits for the host to compute a plan. */
export const PLAN_TRIES = 30;
export const PLAN_INTERVAL = 2000;

/** The shortest reason the control plane records with a deployment. */
export const MIN_REASON = 8;

/** The digest of every service in the plan, by name: what the deployment binds. */
export function planImageDigests(plan: ProjectPlan): Record<string, string> {
  const digests: Record<string, string> = {};
  for (const service of plan.services ?? []) {
    if (service.image_digest) digests[service.name] = service.image_digest;
  }
  return digests;
}

/** Where the plan learned the digest, in the operator's words. */
export function digestSourceWords(source: string): string {
  switch (source) {
    case "reference":
      return "pinned in manifest";
    case "registry":
      return "from registry";
    case "local":
      return "from host image";
    default:
      return source;
  }
}

/** The colour of a change: what goes away is not what arrives. */
export function changeTone(action: string): Tone {
  if (action === "remove") return "error";
  if (action === "create") return "ok";
  return "warn";
}

/** A count of what satisfies a test, or undefined where the list itself is unknown. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

export function Compose({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [project, setProject] = useState("");
  const [manifest, setManifest] = useState("");
  const [plan, setPlan] = useState<ProjectPlan | null>(null);
  const [message, setMessage] = useState("");
  const [reason, setReason] = useState("");
  // The deployment ordered last, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);

  // What may be changed here at all: refused outright, the module stays
  // readable and says what changing it would take.
  const access = useModuleAccess(host.id, COMPOSE_CHANGES);
  const mayPlan = useAllowed(host.id, "docker.compose.plan");
  const mayDeploy = useAllowed(host.id, "docker.compose.deploy");

  const versions = useQuery({
    queryKey: ["compose-versions", host.id, project],
    queryFn: () =>
      api.get<Collection<ProjectVersion>>(
        `/api/v1/hosts/${host.id}/compose/${encodeURIComponent(project)}/versions`,
      ),
    enabled: project.length > 0,
  });

  // The plan is computed on the host, so the screen waits for the
  // operation's result rather than pretending the order was the answer.
  async function awaitPlan(jobID: string) {
    for (let attempt = 0; attempt < PLAN_TRIES; attempt++) {
      await new Promise((done) => setTimeout(done, PLAN_INTERVAL));
      const attempts = await api.get<{ items: { status?: string; detail?: { payload?: ProjectPlan } }[] }>(
        `/api/v1/jobs/${jobID}/attempts`,
      );
      const last = attempts.items[attempts.items.length - 1];
      if (!last?.status) continue;
      if (last.detail?.payload) {
        setPlan(last.detail.payload);
        setMessage("");
        return;
      }
      setMessage(t("Planning finished with status {status} and no plan.", { status: last.status }));
      return;
    }
    setMessage(t("The plan did not arrive in time."));
  }

  const planProject = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.plan",
        payload: { compose: { project, manifest } },
      }),
    onSuccess: (job) => {
      setPlan(null);
      setMessage(t("Planning as job {id}. The result appears below when it finishes.", { id: job.id.slice(0, 8) }));
      void awaitPlan(job.id);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const deploy = useMutation({
    // The deployment carries the plan digest and the image digest of every
    // service: the host resolves the tags once more and refuses when any
    // moved, and the trail says which digests were approved.
    mutationFn: (body: { manifest: string; digest: string; imageDigests: Record<string, string>; reason: string }) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.deploy",
        reason: body.reason,
        payload: {
          compose: { project, manifest: body.manifest, plan_digest: body.digest, image_digests: body.imageDigests },
        },
      }),
    onSuccess: (job) => {
      setOrdered(job);
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["compose-versions", host.id, project] });
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // The deployments of the named project by outcome; without a project
  // there is nothing to count and the band says so with dashes.
  const history = project ? versions.data?.items : undefined;
  const outcomes: Segment[] = [
    { label: t("applied"), value: countWhere(history, (one) => one.applied), tone: "ok" },
    { label: t("failed"), value: countWhere(history, (one) => !one.applied && one.state === "failed"), tone: "error" },
    { label: t("other"), value: countWhere(history, (one) => !one.applied && one.state !== "failed"), tone: "unknown" },
  ];

  const changes = Object.entries((plan?.changes ?? []).reduce<Record<string, number>>((all, change) => {
    all[change.action] = (all[change.action] ?? 0) + 1;
    return all;
  }, {})).sort((a, b) => b[1] - a[1]);

  const readOnly = access.known && !access.anyAllowed
    ? access.permissions.length > 0 && access.reasons.length === 0
      ? t("You can read this module; changing it needs the permission {permissions}.", {
          permissions: access.permissions.join(", "),
        })
      : t("You can read this module; changing it is not possible here: {reasons}", {
          reasons: [
            ...access.reasons,
            ...access.permissions.map((one) => t("missing permission {permission}", { permission: one })),
          ].join("; "),
        })
    : "";

  const reasonReady = reason.trim().length >= MIN_REASON;

  return (
    <Board
      screen={HOST_COMPOSE_SCREEN}
      catalogue={HOST_COMPOSE}
      notices={stacked(
        readOnly && <Banner tone="info">{readOnly}</Banner>,
        message && <Problem>{message}</Problem>,
        ordered && (
          <Banner tone="ok">
            {ordered.requires_approval
              ? t("The deployment is waiting for approval.")
              : t("The deployment has been queued.")}
            {" "}
            <Link to={`/next/jobs/${ordered.id}`}>{t("job {id}", { id: ordered.id.slice(0, 8) })}</Link>
            {" · "}
            <Link to={`/next/hosts/${host.id}/jobs`}>{t("See all jobs")}</Link>
          </Banner>
        ),
      )}
      drawn={{
      deployments: (
        <Card
          title={t("Deployments")}
          note={project
            ? t("Every deployment of {project} from the panel.", { project })
            : t("Name a project to see its deployment history.")}
        >
          <Band segments={outcomes} testId="deployments" />
        </Card>
      ),
      changes_by_kind: (
        <Card title={t("What the plan would change")} note={t("By kind of change.")}>
          {!plan
            ? <Empty icon="compose">{t("No plan yet.")}</Empty>
            : changes.length === 0
              ? <Empty>{t("Nothing would change on this host.")}</Empty>
              : (
                <Bars items={changes.map(([action, count]) => ({
                  label: t(action), value: count, tone: changeTone(action),
                }))} />
              )}
        </Card>
      ),
      project: (
        <Card
          title={t("Project")}
          note={t("Docker Compose projects deployed from the panel: plan first, then deploy exactly that plan.")}
          foot={t("The manifest is stored with the operation and stays in the panel's history. Keep credentials out of it.")}
        >
          <Stack>
            <Fields>
              <Field label={t("Project name")}>
                <input
                  value={project}
                  onChange={(event) => setProject(event.target.value)}
                  placeholder="shop"
                  data-testid="project"
                />
              </Field>
              <Field label={t("Manifest (docker-compose.yml)")} wide>
                <textarea
                  rows={12}
                  value={manifest}
                  onChange={(event) => { setManifest(event.target.value); setPlan(null); }}
                  placeholder={"services:\n  web:\n    image: nginx@sha256:…"}
                  data-testid="manifest"
                />
              </Field>
            </Fields>
            <Actions>
              {/* The plan is the one button of this card: refused, it stays
                  on the screen disabled with the reason beside it. */}
              {(mayPlan.allowed || mayPlan.known) && (
                <Button
                  onClick={() => planProject.mutate()}
                  disabled={!mayPlan.allowed || planProject.isPending || !project || !manifest}
                  title={mayPlan.allowed ? undefined : mayPlan.reason || t("This action is not available.")}
                  testId="plan"
                >
                  {planProject.isPending ? t("Planning…") : t("Plan")}
                </Button>
              )}
              {!mayPlan.allowed && !mayPlan.pending && mayPlan.known && (
                <Note>{mayPlan.reason || t("This action is not available.")}</Note>
              )}
            </Actions>
          </Stack>
        </Card>
      ),
      history: (
        <Card title={t("History")} flush note={project ? undefined : t("Name a project to see its deployment history.")}>
          <Table
            rows={project ? versions.data?.items ?? [] : []}
            keyOf={(one) => one.job_id}
            rowTestId={(one) => `version-${one.job_id}`}
            testId="history"
            loading={project.length > 0 && versions.isLoading}
            empty={project
              ? t("This project has not been deployed from the panel yet.")
              : t("Name a project to see its deployment history.")}
            columns={[
              { key: "when", head: t("When"), cell: (one) => (
                <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
              ) },
              { key: "by", head: t("By"), minor: true, tight: true, cell: (one) => one.created_by },
              { key: "state", head: t("State"), cell: (one) => (
                <Pill tone={one.applied ? "ok" : one.state === "failed" ? "error" : "unknown"}>
                  {t(stateName(one.state))}
                </Pill>
              ) },
              { key: "digest", head: t("Plan"), tight: true, cell: (one) => (
                one.plan_digest
                  ? <code title={one.plan_digest}>{one.plan_digest.slice(0, 12)}</code>
                  : <span className="fl-faint">—</span>
              ) },
              { key: "load", actions: true, cell: (one) => (
                // Rolling a change back is deploying an earlier version. It
                // is loaded into the editor so that it goes through a plan:
                // the host's state may have moved since then.
                <Button
                  kind="quiet"
                  onClick={() => { setManifest(one.manifest); setPlan(null); }}
                  testId={`load-${one.job_id}`}
                >
                  {t("Load into editor")}
                </Button>
              ) },
            ]}
          />
        </Card>
      ),
      plan: (
        <Card
          title={t("Plan")}
          flush
          note={plan
            ? t("Digest {digest} · deploying uses exactly this plan; if the manifest or the images change, the deployment is refused.", {
                digest: plan.digest.slice(0, 16),
              })
            : undefined}
        >
          {!plan ? <Empty icon="compose">{t("No plan yet.")}</Empty> : (
            <>
              {(plan.warnings ?? []).map((warning) => (
                <Banner key={warning} tone="warn">{warning}</Banner>
              ))}
              <Table
                rows={plan.changes ?? []}
                keyOf={(one) => `${one.kind}/${one.name}`}
                testId="plan-changes"
                empty={t("Nothing would change on this host.")}
                columns={[
                  { key: "kind", head: t("Object"), cell: (one) => one.kind },
                  { key: "name", head: t("Name"), tight: true, cell: (one) => <code title={one.name}>{one.name}</code> },
                  { key: "action", head: t("Change"), cell: (one) => (
                    <Pill tone={changeTone(one.action)}>{t(one.action)}</Pill>
                  ) },
                ]}
              />
            </>
          )}
        </Card>
      ),
      services: (
        <Card
          title={t("Services after deployment")}
          flush
          note={t("Each service runs the digest shown here; a tag that points at another digest by the time of deployment makes the plan stale.")}
        >
          <Table
            rows={plan?.services ?? []}
            keyOf={(one) => one.name}
            testId="plan-services"
            empty={plan ? t("The plan names no service.") : t("No plan yet.")}
            columns={[
              { key: "name", head: t("Service"), tight: true, cell: (one) => <code title={one.name}>{one.name}</code> },
              { key: "image", head: t("Image"), tight: true, cell: (one) => <code title={one.image}>{one.image}</code> },
              // The digest is the identity of what runs; the tag is what the
              // operator wrote. Both are here so a moved tag can be read off
              // the plan rather than discovered by the refusal.
              { key: "digest", head: t("Digest that will run"), tight: true, cell: (one) => (
                one.image_digest
                  ? (
                    <span title={one.pinned_image}>
                      <code>{`${one.image_digest.replace(/^sha256:/, "").slice(0, 16)}…`}</code>
                      {one.digest_source && <Pill dot={false}>{t(digestSourceWords(one.digest_source))}</Pill>}
                    </span>
                  )
                  : <Pill tone="unknown">{t("unresolved")}</Pill>
              ) },
              { key: "replicas", head: t("Replicas"), num: true, cell: (one) => one.replicas ?? 1 },
            ]}
          />
        </Card>
      ),
      deploy: (
        <Card
          title={t("Deploy this plan")}
          note={t("A deployment is kept in the trail with the reason it was given.")}
        >
          {!plan ? <Empty icon="compose">{t("Plan first; a deployment is of a plan, never of a manifest.")}</Empty> : (
            <Stack>
              <Readout
                label={t("The plan this consent binds")}
                value={plan.digest}
                testId="plan-digest"
              />
              <Fields>
                <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
                  <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
                </Field>
              </Fields>
              <Actions>
                {(mayDeploy.allowed || mayDeploy.known) && (
                  <Button
                    kind="danger"
                    disabled={!mayDeploy.allowed || deploy.isPending || !reasonReady}
                    title={mayDeploy.allowed
                      ? reasonReady ? undefined : t("The deployment is recorded with a reason of at least 8 characters.")
                      : mayDeploy.reason || t("This action is not available.")}
                    onClick={() => deploy.mutate({
                      manifest, digest: plan.digest, imageDigests: planImageDigests(plan), reason,
                    })}
                    testId="deploy"
                  >
                    {deploy.isPending ? t("Requesting…") : t("Deploy this plan")}
                  </Button>
                )}
              </Actions>
              {!mayDeploy.allowed && !mayDeploy.pending && mayDeploy.known && (
                <Note>{mayDeploy.reason || t("This action is not available.")}</Note>
              )}
            </Stack>
          )}
        </Card>
      ),
    }} />
  );
}

/** The name this screen's arrangement is stored under. */
export const HOST_COMPOSE_SCREEN = "next_host_compose";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_COMPOSE: BoardEntry[] = [
  { key: "deployments", title: "Deployments", width: 8, height: 2 },
  { key: "changes_by_kind", title: "What the plan would change", width: 4, height: 2 },
  { key: "project", title: "Project", width: 7, height: 4 },
  { key: "history", title: "History", width: 5, height: 4 },
  { key: "plan", title: "Plan", width: 6, height: 3 },
  { key: "services", title: "Services after deployment", width: 6, height: 3 },
  { key: "deploy", title: "Deploy this plan", width: 12, height: 2 },
];
