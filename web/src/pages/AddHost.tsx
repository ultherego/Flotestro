import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type StepState = "waiting" | "done" | "failed";

type InstallationStep = {
  key: "token" | "certificate" | "connected" | "inventory";
  state: StepState;
};

type Order = {
  id: string;
  description?: string;
  site: string;
  environment: string;
  kind: "agent" | "relay";
  purpose: "new" | "replace_identity" | "relay";
  max_uses: number;
  uses: number;
  status: "pending" | "enrolled" | "expired" | "revoked" | "failed";
  enrolled_host_id?: string;
  expires_at: string;
  created_by: string;
  created_at: string;
  steps?: InstallationStep[];
};

/** The order right after creation - the only moment the token exists. */
type NewOrder = Order & { token: string };

/** The installation step described in the operator's language, not the code's. */
const stepDescriptions: Record<InstallationStep["key"], string> = {
  token: "token accepted",
  certificate: "certificate issued",
  connected: "agent online",
  inventory: "inventory received",
};

/** The step state mark. Colour alone is not enough: the state must be readable. */
function stepMark(state: StepState): string {
  if (state === "done") return "✓";
  if (state === "failed") return "✕";
  return "…";
}

/**
 * Adding a host to the fleet.
 *
 * The screen leads through one decision at a time and shows live what the
 * host has already done. The token appears only after the order is created
 * and does not come back after a page refresh: it is a one-time secret, not
 * a field to read. The panel does not compose a shell command with the token
 * inside for the operator - the token is pasted into the hidden prompt of
 * the tool on the host.
 */
export function AddHost() {
  const t = useT();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [description, setDescription] = useState("");
  const [site, setSite] = useState("default");
  const [environment, setEnvironment] = useState("unassigned");
  const [minutes, setMinutes] = useState(15);
  const [family, setFamily] = useState<"debian" | "rpm">("debian");
  const [created, setCreated] = useState<NewOrder | null>(null);
  const [copied, setCopied] = useState(false);
  const [message, setMessage] = useState("");

  const list = useQuery({
    queryKey: ["enrollment-requests"],
    queryFn: () => api.get<{ items: Order[] }>("/api/v1/enrollment-requests"),
  });

  // The installation progress refreshes itself as long as something can still change.
  const progress = useQuery({
    queryKey: ["enrollment-request", created?.id],
    queryFn: () => api.get<Order>(`/api/v1/enrollment-requests/${created?.id}`),
    enabled: !!created,
    refetchInterval: (query) =>
      query.state.data?.status === "pending" ? 3000 : false,
  });

  const order = useMutation({
    mutationFn: () =>
      api.post<NewOrder>("/api/v1/enrollment-requests", {
        description,
        site,
        environment,
        ttl_minutes: minutes,
      }),
    onSuccess: (result) => {
      setCreated(result);
      setCopied(false);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/enrollment-requests/${id}/revoke`, {}),
    onSuccess: (_result, id) => {
      if (created?.id === id) setCreated(null);
      setMessage(t("Enrollment request revoked; the token no longer works."));
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (list.error) return <ErrorBox error={list.error} />;

  const state = progress.data ?? created;
  const steps = state?.steps ?? [];
  const hostReady = state?.enrolled_host_id;
  const pending = (list.data?.items ?? []).filter((entry) => entry.status === "pending");

  return (
    <>
      <h1>{t("Add host")}</h1>
      <p className="subtitle">
        {t("A host joins the fleet by proving it holds a one-time token, then keeping the certificate the panel issues for it. The token is shown once, here, and never again — it is not stored in this browser and cannot be read back from the panel.")}
      </p>

      {!created ? (
        <div className="form">
          <h2>{t("1. What is being installed")}</h2>
          <label>
            {t("What this host is for")}
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t("web-042, Warsaw production")}
            />
          </label>
          <div className="grid-two">
            <label>
              {t("Site")}
              <input value={site} onChange={(e) => setSite(e.target.value)} />
            </label>
            <label>
              {t("Environment")}
              <input value={environment} onChange={(e) => setEnvironment(e.target.value)} />
            </label>
          </div>
          <label>
            {/* A short deadline is a safeguard, not an inconvenience: a token
                that lies around for hours is a secret waiting to leak. */}
            {t("Token valid for (minutes, at most 24 h)")}
            <input
              type="number"
              min={1}
              max={1440}
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
            />
          </label>
          <div className="operations">
            <button onClick={() => order.mutate()} disabled={order.isPending}>
              {t("Create enrollment token")}
            </button>
          </div>
        </div>
      ) : (
        <div className="form">
          <h2>{t("2. Install on the host")}</h2>
          <p className="source">
            {t("Site {site} · environment {environment} · token expires", { site: created.site, environment: created.environment })}{" "}
            <Time value={created.expires_at} />
          </p>

          <div className="operations" style={{ marginBottom: 12 }}>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(created.token);
                setCopied(true);
              }}
            >
              {copied ? t("Token copied") : t("Copy token")}
            </button>
            <span className="source">
              {t("Shown once. Paste it into the hidden prompt on the host; do not put it in a shell command — the command line is visible to every user of that machine.")}
            </span>
          </div>

          <div className="operations" style={{ marginBottom: 12 }}>
            <button
              className={family === "debian" ? "" : "secondary"}
              onClick={() => setFamily("debian")}
            >
              Debian / Ubuntu
            </button>
            <button
              className={family === "rpm" ? "" : "secondary"}
              onClick={() => setFamily("rpm")}
            >
              Fedora / RHEL
            </button>
          </div>
          <ol className="steps">
            <li>
              {t("Install the agent package")}
              <pre>
                {family === "debian"
                  ? "sudo apt-get install flotestro-agent"
                  : "sudo dnf install flotestro-agent"}
              </pre>
            </li>
            <li>
              {t("Point it at this panel in")} <code>/etc/flotestro/agent.yaml</code>
              <pre>
                {`connection:\n  enrollment_url: "${window.location.origin.replace(/:\d+$/, ":8444")}"\n  gateway_urls: ["${window.location.origin.replace(/:\d+$/, ":8443")}"]`}
              </pre>
            </li>
            <li>
              {t("Register the host and paste the token when asked")}
              <pre>sudo -u flotestro-agent flotestro-agentctl enroll</pre>
            </li>
            <li>
              {t("Start the agent")}
              <pre>sudo systemctl start flotestro-agent.service</pre>
            </li>
          </ol>

          <h2>{t("3. Enrollment status")}</h2>
          <ul className="steps" aria-live="polite">
            {steps.map((step) => (
              <li key={step.key}>
                <span className={`badge ${step.state === "done" ? "ok" : step.state === "failed" ? "warn" : "unknown"}`}>
                  {stepMark(step.state)}
                </span>{" "}
                {t(stepDescriptions[step.key])}
              </li>
            ))}
            {!steps.length && <li className="source">{t("waiting for the host…")}</li>}
          </ul>

          <div className="operations">
            {hostReady && (
              <button onClick={() => navigate(`/hosts/${hostReady}/overview`)}>
                {t("Open host")}
              </button>
            )}
            <button className="secondary" onClick={() => revoke.mutate(created.id)}>
              {t("Revoke token")}
            </button>
            <button className="secondary" onClick={() => setCreated(null)}>
              {t("Add another host")}
            </button>
          </div>
        </div>
      )}

      {message && <p className="source" style={{ margin: "12px 0" }}>{message}</p>}

      <h2>{t("Pending installations")}</h2>
      {!pending.length ? (
        <Empty>{t("No installation is waiting for a host right now.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("What for")}</th><th>{t("Scope")}</th><th>{t("Uses")}</th><th>{t("Expires")}</th><th>{t("Requested by")}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {pending.map((entry) => (
              <tr key={entry.id}>
                <td>
                  {entry.description || "—"}
                  <div className="source">{entry.purpose}</div>
                </td>
                <td className="source">{entry.site} / {entry.environment}</td>
                <td className="source">{entry.uses} / {entry.max_uses}</td>
                <td className="source"><Time value={entry.expires_at} /></td>
                <td className="source">{entry.created_by}</td>
                <td>
                  <button className="secondary" onClick={() => revoke.mutate(entry.id)}>
                    {t("Revoke")}
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
