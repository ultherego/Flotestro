import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty, JobState } from "../../components/ui";
import { useHost } from "./shared";
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

type PlanService = { name: string; image: string; image_digest?: string; replicas?: number };
type PlanChange = { kind: string; name: string; action: string };
type ProjectPlan = {
  project: string;
  digest: string;
  services?: PlanService[];
  changes?: PlanChange[];
  warnings?: string[];
};

/**
 * Docker Compose projects.
 *
 * The manifest describes the desired state, not a command. The operator
 * plans, looks at the differences and only then deploys - the deployment is
 * bound to that plan and refuses when the base state changed since the
 * approval.
 */
export function Compose() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const [project, setProject] = useState("");
  const [manifest, setManifest] = useState("");
  const [plan, setPlan] = useState<ProjectPlan | null>(null);
  const [message, setMessage] = useState("");

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
  // operation's result. The stream wakes the job list; here it is enough to
  // poll for this one result.
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
    mutationFn: (body: { manifest: string; digest: string; reason: string }) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.deploy",
        reason: body.reason,
        payload: {
          compose: { project, manifest: body.manifest, plan_digest: body.digest },
        },
      }),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      queryClient.invalidateQueries({ queryKey: ["compose-versions", host.id, project] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  return (
    <>
      <h2>{t("Project")}</h2>
      <div className="form">
        <label>
          {t("Project name")}
          <input
            value={project}
            onChange={(e) => setProject(e.target.value)}
            placeholder="shop"
          />
        </label>
        <label>
          {t("Manifest (docker-compose.yml)")}
          <textarea
            rows={12}
            value={manifest}
            onChange={(e) => { setManifest(e.target.value); setPlan(null); }}
            placeholder={"services:\n  web:\n    image: nginx@sha256:…"}
          />
        </label>
        <div className="operations">
          <button
            onClick={() => planProject.mutate()}
            disabled={planProject.isPending || !project || !manifest}
          >
            {planProject.isPending ? t("Planning…") : t("Plan")}
          </button>
        </div>
        {/* The manifest is stored in the panel together with the version
            history, so a password typed into it stops being a secret. */}
        <p className="source" style={{ margin: 0 }}>
          {t("The manifest is stored with the operation and stays in the panel's history. Keep credentials out of it.")}
        </p>
      </div>

      {message && <p className="source" style={{ marginTop: 12 }}>{message}</p>}

      {plan && (
        <>
          <h2>{t("Plan")}</h2>
          <p className="subtitle">
            {t("Digest {digest} · deploying uses exactly this plan; if the manifest or the images change, the deployment is refused.", { digest: plan.digest.slice(0, 16) })}
          </p>

          {plan.warnings?.map((warning) => (
            <p key={warning} className="warning"><span>{warning}</span></p>
          ))}

          <table>
            <thead><tr><th>{t("Object")}</th><th>{t("Name")}</th><th>{t("Change")}</th></tr></thead>
            <tbody>
              {!plan.changes?.length ? (
                <tr><td colSpan={3} className="empty">{t("Nothing would change on this host.")}</td></tr>
              ) : (
                plan.changes.map((change) => (
                  <tr key={`${change.kind}/${change.name}`}>
                    <td>{change.kind}</td>
                    <td>{change.name}</td>
                    <td>{change.action}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <h2>{t("Services after deployment")}</h2>
          <table>
            <thead><tr><th>{t("Service")}</th><th>{t("Image")}</th><th>{t("Replicas")}</th></tr></thead>
            <tbody>
              {(plan.services ?? []).map((service) => (
                <tr key={service.name}>
                  <td>{service.name}</td>
                  <td>{service.image}</td>
                  <td>{service.replicas ?? 1}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <DeployConfirmation
            busy={deploy.isPending}
            onDeploy={(reason) => deploy.mutate({ manifest, digest: plan.digest, reason })}
          />
        </>
      )}

      <h2>{t("History")}</h2>
      {!project ? (
        <Empty>{t("Name a project to see its deployment history.")}</Empty>
      ) : !versions.data?.items.length ? (
        <Empty>{t("This project has not been deployed from the panel yet.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("When")}</th><th>{t("By")}</th><th>{t("State")}</th><th>{t("Plan")}</th><th></th></tr></thead>
          <tbody>
            {versions.data.items.map((version) => (
              <tr key={version.job_id}>
                <td><Time value={version.created_at} /></td>
                <td>{version.created_by}</td>
                <td><JobState state={version.state} /></td>
                <td>{version.plan_digest?.slice(0, 12) || "—"}</td>
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
        </table>
      )}
    </>
  );
}

/** A deployment is a critical operation, so it needs a justification in the audit. */
function DeployConfirmation({
  onDeploy, busy,
}: { onDeploy: (reason: string) => void; busy: boolean }) {
  const t = useT();
  const [reason, setReason] = useState("");
  return (
    <div className="form" style={{ marginTop: 16 }}>
      <label>
        {t("Reason (at least 8 characters, kept in the audit trail)")}
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <div className="operations">
        <button disabled={busy || reason.trim().length < 8} onClick={() => onDeploy(reason)}>
          {busy ? t("Requesting…") : t("Deploy this plan")}
        </button>
      </div>
    </div>
  );
}
