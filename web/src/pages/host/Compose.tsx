import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty, JobState } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Field, Fields, Form, FormActions, FormNote, JobNotice, Message, ModuleHeader, ModulePage, Section, Summary, Table, Widgets,
  countWhere, useHost,
} from "./shared";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import { useT } from "../../i18n";

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

/**
 * Docker Compose projects. The manifest describes the desired state, not a
 * command.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const COMPOSE_CHANGES = ["docker.compose.deploy"];

export function Compose() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [project, setProject] = useState("");
  const [manifest, setManifest] = useState("");
  const [plan, setPlan] = useState<ProjectPlan | null>(null);
  const [message, setMessage] = useState("");
  // The deployment ordered last, linked where its sentence stands.
  const [ordered, setOrdered] = useState<Job | null>(null);

  const versions = useQuery({
    queryKey: ["compose-versions", host.id, project],
    queryFn: () =>
      api.get<Collection<ProjectVersion>>(
        `/api/v1/hosts/${host.id}/compose/${encodeURIComponent(project)}/versions`,
      ),
    enabled: project.length > 0,
  });

  const planProject = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.plan",
        payload: { compose: { project, manifest } },
      }),
    onSuccess: (job) => {
      setPlan(null);
      setMessage(t("Planning as job {id}. The result appears below when it finishes.", { id: job.id.slice(0, 8) }));
      awaitPlan(job.id);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // The plan is computed on the host, so the screen waits for the
  // operation's result.
  async function awaitPlan(jobID: string) {
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise((done) => setTimeout(done, 2000));
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

  const deploy = useMutation({
    // The deployment carries the plan digest and the image digest of every
    // service: the host resolves the tags once more and refuses when any
    // moved, and the audit trail says which digests were approved.
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
      queryClient.invalidateQueries({ queryKey: ["compose-versions", host.id, project] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  // The deployments of the named project by outcome; without a project
  // there is nothing to count and the bar shows dashes.
  const history = project ? versions.data?.items : undefined;
  const changes = Object.entries((plan?.changes ?? []).reduce<Record<string, number>>((acc, change) => {
    acc[change.action] = (acc[change.action] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Compose")}
        description={t("Docker Compose projects deployed from the panel: plan first, then deploy exactly that plan.")}
      />
      <ReadOnlyModuleNotice host={host.id} actions={COMPOSE_CHANGES} />
      <Message text={message} />
      {ordered && <JobNotice job={ordered} hostID={host.id} />}

      <Widgets>
      {/* The project's deployments by outcome, and the plan's changes by
          kind once there is a plan. */}
      <Summary
        title={t("Deployments")}
        description={project ? t("Every deployment of {project} from the panel.", { project }) : t("Name a project to see its deployment history.")}
        span={8}
        segments={[
          { label: t("applied"), value: countWhere(history, (version) => version.applied), tone: "ok" },
          { label: t("failed"), value: countWhere(history, (version) => !version.applied && version.state === "failed"), tone: "error" },
          { label: t("other"), value: countWhere(history, (version) => !version.applied && version.state !== "failed"), tone: "unknown" },
        ]}
      />
      <Section title={t("Plan")} span={4} description={t("What the plan would change on this host, by kind.")}>
        {!plan ? (
          <p className="source" style={{ margin: 0 }}>{t("No plan yet.")}</p>
        ) : !changes.length ? (
          <p className="source" style={{ margin: 0 }}>{t("Nothing would change on this host.")}</p>
        ) : (
          <Breakdown
            items={changes.map(([action, count]) => ({
              label: action, value: count, tone: action === "remove" ? "error" as const : action === "create" ? "ok" as const : "warn" as const,
            }))}
          />
        )}
      </Section>

      {/* The editor and the project's history side by side: a manifest is
          written with the previous deployments in view. The plan, once
          there is one, follows as a pair of tables and the consent below. */}
      <Section title={t("Project")} span={7}>
        <Form>
          <Fields>
            <Field label={t("Project name")}>
              <input
                value={project}
                onChange={(e) => setProject(e.target.value)}
                placeholder="shop"
              />
            </Field>
            <Field label={t("Manifest (docker-compose.yml)")} wide>
              <textarea
                rows={12}
                value={manifest}
                onChange={(e) => { setManifest(e.target.value); setPlan(null); }}
                placeholder={"services:\n  web:\n    image: nginx@sha256:…"}
              />
            </Field>
          </Fields>
          <FormActions>
            <ActionGuard action="docker.compose.plan" host={host.id} explain>
              <button
                onClick={() => planProject.mutate()}
                disabled={planProject.isPending || !project || !manifest}
              >
                {planProject.isPending ? t("Planning…") : t("Plan")}
              </button>
            </ActionGuard>
          </FormActions>
          {/* The manifest is stored in the panel together with the version
              history, so a password typed into it stops being a secret. */}
          <FormNote>
            {t("The manifest is stored with the operation and stays in the panel's history. Keep credentials out of it.")}
          </FormNote>
        </Form>
      </Section>

      <Section title={t("History")} count={project ? versions.data?.items.length : undefined} span={5} flush>
        {!project ? (
          <Empty>{t("Name a project to see its deployment history.")}</Empty>
        ) : !versions.data?.items.length ? (
          <Empty>{t("This project has not been deployed from the panel yet.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("When")}</th><th>{t("By")}</th><th>{t("State")}</th><th>{t("Plan")}</th><th></th></tr></thead>
            <tbody>
              {versions.data.items.map((version) => (
                <tr key={version.job_id}>
                  <td><Time value={version.created_at} /></td>
                  <td>{version.created_by}</td>
                  <td><JobState state={version.state} /></td>
                  <td className="hm-mono">{version.plan_digest?.slice(0, 12) || "—"}</td>
                  <td>
                    {/* Rolling a change back is deploying an earlier version.
                        It is loaded into the editor so that it goes through
                        a plan - the host state may have changed since then. */}
                    <button
                      className="secondary"
                      onClick={() => { setManifest(version.manifest); setPlan(null); }}
                    >
                      {t("Load into editor")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      {plan && (
        <>
          <Section
            title={t("Plan")}
            count={plan.changes?.length ?? 0}
            span={6}
            description={t("Digest {digest} · deploying uses exactly this plan; if the manifest or the images change, the deployment is refused.", { digest: plan.digest.slice(0, 16) })}
            flush
          >
            {plan.warnings?.map((warning) => (
              <p key={warning} className="warning"><span>{warning}</span></p>
            ))}

            <Table>
              <thead><tr><th>{t("Object")}</th><th>{t("Name")}</th><th>{t("Change")}</th></tr></thead>
              <tbody>
                {!plan.changes?.length ? (
                  <tr><td colSpan={3} className="empty">{t("Nothing would change on this host.")}</td></tr>
                ) : (
                  plan.changes.map((change) => (
                    <tr key={`${change.kind}/${change.name}`}>
                      <td>{change.kind}</td>
                      <td className="hm-mono">{change.name}</td>
                      <td>{change.action}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </Table>
          </Section>

          <Section
            title={t("Services after deployment")}
            count={(plan.services ?? []).length}
            span={6}
            description={t("Each service runs the digest shown here; a tag that points at another digest by the time of deployment makes the plan stale.")}
            flush
          >
            <Table>
              <thead><tr><th>{t("Service")}</th><th>{t("Image")}</th><th>{t("Digest that will run")}</th><th className="hm-num">{t("Replicas")}</th></tr></thead>
              <tbody>
                {(plan.services ?? []).map((service) => (
                  <tr key={service.name}>
                    <td className="hm-mono hm-primary">{service.name}</td>
                    <td className="hm-mono">{service.image}</td>
                    {/* The digest is the identity of what runs; the tag is what
                        the operator wrote. Both are shown so a moved tag can be
                        read off the plan. */}
                    <td className="hm-mono" title={service.pinned_image}>
                      {service.image_digest ? (
                        <>
                          {service.image_digest.replace(/^sha256:/, "").slice(0, 16)}…
                          {service.digest_source && <span className="badge"> {t(digestSourceWords(service.digest_source))}</span>}
                        </>
                      ) : (
                        <span className="badge unknown">{t("unresolved")}</span>
                      )}
                    </td>
                    <td className="hm-num">{service.replicas ?? 1}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Section>

          <ActionGuard action="docker.compose.deploy" host={host.id}>
            <DeployConfirmation
              busy={deploy.isPending}
              onDeploy={(reason) => deploy.mutate({ manifest, digest: plan.digest, imageDigests: planImageDigests(plan), reason })}
            />
          </ActionGuard>
        </>
      )}
      </Widgets>
    </ModulePage>
  );
}

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

/** A deployment is a critical operation, so it needs a justification in the audit. */
function DeployConfirmation({
  onDeploy, busy,
}: { onDeploy: (reason: string) => void; busy: boolean }) {
  const t = useT();
  const [reason, setReason] = useState("");
  return (
    <Section title={t("Deploy this plan")} span={12}>
      <Form>
        <Fields>
          <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
        </Fields>
        <FormActions>
          <button disabled={busy || reason.trim().length < 8} onClick={() => onDeploy(reason)}>
            {busy ? t("Requesting…") : t("Deploy this plan")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
