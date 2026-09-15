import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import { useEnrollmentStream } from "../lib/stream";
import type {
  EnrollmentOrder, EnrollmentStep, EnrollmentStepState, InstallationCommand,
  InstallationProfile, Relay, Whoami,
} from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Actions, Card, Columns, Field, FieldGrid, PageHeader } from "../components/layout";
import { FacetList, useFleetFacets } from "./Bulk";
import { useT } from "../i18n";

/** The order right after creation - the only moment the token exists. */
type NewOrder = EnrollmentOrder & { token: string };

/** The wizard steps, in the order the operator decides them. */
const STEPS = ["Type", "Assignment", "Connection", "System", "Installation", "Status"] as const;

/** The distribution families the release packages; the keys match the profile. */
const FAMILIES = [
  { key: "debian", label: "Debian" },
  { key: "ubuntu", label: "Ubuntu" },
  { key: "rhel", label: "RHEL / Fedora" },
  { key: "arch", label: "Arch Linux" },
];

/** The installation step described in the operator's language, not the code's. */
const stepDescriptions: Record<EnrollmentStep["key"], string> = {
  token: "token accepted",
  certificate: "certificate issued",
  connected: "agent online",
  inventory: "inventory received",
};

/** The command titles, by the stable key the profile names each step with. */
const commandTitles: Record<InstallationCommand["key"], string> = {
  repository: "Add the signed repository",
  package: "Install the agent package",
  config: "Save the configuration",
  ca: "Save the fleet CA and compare the fingerprint",
  enroll: "Register the host and paste the token when asked",
  start: "Start the agent",
};

/**
 * What an error code means for the person at the screen. Only the codes
 * the panel really records are here; the rest show as they came, with the
 * sentence the server attached.
 */
const errorDescriptions: Record<string, string> = {
  token_expired: "The token expired before the host used it. Regenerate the order and try again.",
  token_revoked: "The order was revoked; its token no longer works.",
  enrollment_request_reused: "The order was already used up. Another host needs another order.",
  machine_id_mismatch: "The machine is not the one the order was bound to.",
  relay_scope_mismatch: "The host came by a route the order does not allow: directly instead of through the relay, or through the relay of another site.",
  duplicate_machine_id: "The machine is already in the fleet under another host; a new-host token does not fit it. Use identity recovery on that host instead.",
  csr_invalid: "The certificate request from the host was refused. Check the agent journal on the host.",
  host_retired: "The host was decommissioned and does not come back with a token.",
  machine_id_retired: "The machine belongs to a retired host and is held back for the retention period; a new-host token does not fit it yet.",
  enrolled_not_connected: "The certificate was issued, but no session has opened. Check that the service runs and that the gateway address is reachable from the host.",
  inventory_unavailable: "The agent is connected, but no inventory has arrived. Check the agent journal for a module that fails to read the host.",
};

/** The step state mark. Colour alone is not enough: the state must be readable. */
function stepMark(state: EnrollmentStepState): string {
  if (state === "done") return "✓";
  if (state === "failed") return "✕";
  return "…";
}

/** A host is ready when every stage is done: session, capabilities and a first inventory. */
function hostReady(order?: EnrollmentOrder | null): boolean {
  return !!order?.enrolled_host_id && !!order.steps?.length &&
    order.steps.every((step) => step.state === "done");
}

/** The time left on a token, as minutes and seconds; empty once it has passed. */
function timeLeft(expiresAt: string, now: number): string {
  const left = Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000));
  const minutes = Math.floor(left / 60);
  const seconds = left % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

/**
 * Adding a host to the fleet.
 *
 * The wizard leads through one decision at a time - what, where, by which
 * route, on which system - and only then places the order. The token
 * appears once, after the order, and does not come back after a page
 * refresh: it is a one-time secret, kept in the memory of this component
 * alone - not in the address, not in the browser storage. The panel does
 * not compose a shell command with the token inside; the token is pasted
 * into the hidden prompt of the tool on the host.
 *
 * The last step shows live what the host has already done, and names the
 * reason when it stops - as far as the panel can know it.
 */
export function AddHost() {
  const t = useT();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [step, setStep] = useState(0);
  const [kind, setKind] = useState<"agent" | "relay">("agent");
  const [description, setDescription] = useState("");
  const [site, setSite] = useState("default");
  const [environment, setEnvironment] = useState("unassigned");
  const [reason, setReason] = useState("");
  // What the operator already knows about the machine: it goes onto the
  // host the moment it enrolls, so a host that appears at night appears
  // as somebody's and inside the campaigns its tags select.
  const [owner, setOwner] = useState("");
  const [tags, setTags] = useState("");
  const [maxUses, setMaxUses] = useState(1);
  const [minutes, setMinutes] = useState(15);
  const [route, setRoute] = useState<"direct" | "relay">("direct");
  const [relayId, setRelayId] = useState("");
  const [family, setFamily] = useState("debian");
  const [architecture, setArchitecture] = useState("amd64");
  const [created, setCreated] = useState<NewOrder | null>(null);
  const [copied, setCopied] = useState("");
  const [message, setMessage] = useState("");
  const [refusal, setRefusal] = useState<ApiError | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = whoami.data?.permissions ?? [];
  const canEnrollRelay = permissions.includes("relay.enroll.create");
  // A token for many machines is a separate right on top of inviting
  // one; without it the field is not shown, so the order is not refused
  // after the form is filled in.
  const canEnrollBatch = permissions.includes("host.enroll.batch");

  const list = useQuery({
    queryKey: ["enrollment-requests"],
    queryFn: () => api.get<{ items: EnrollmentOrder[] }>("/api/v1/enrollment-requests"),
  });

  // The placement the fleet already has, offered under the inputs.
  const facets = useFleetFacets();
  // The typed placement reaches the server after a pause, not per keystroke.
  const settledSite = useDebounced(site.trim());
  const settledEnvironment = useDebounced(environment.trim());

  // The relays of the chosen site: a token bound to one works only through
  // it, so the list is narrowed to where the host will live.
  const relays = useQuery({
    queryKey: ["relays", settledSite],
    queryFn: () => api.get<{ items: Relay[] }>(`/api/v1/relays?site=${encodeURIComponent(settledSite)}`),
    enabled: kind === "agent" && settledSite !== "",
  });
  const usableRelays = (relays.data?.items ?? []).filter((relay) => !relay.revoked_at);

  // The profile for the placement: it says whether the order needs a
  // reason, and carries the configuration, the trust and the commands.
  // Nothing in it is secret, so it is read as soon as the placement is
  // known and again whenever it changes.
  const profileParams = new URLSearchParams({
    site: settledSite, environment: settledEnvironment, kind, architecture,
  });
  if (kind === "agent" && route === "relay" && relayId) profileParams.set("relay_id", relayId);
  const profile = useQuery({
    queryKey: ["installation-profile", profileParams.toString()],
    queryFn: () => api.get<InstallationProfile>(`/api/v1/installation-profiles?${profileParams}`),
    enabled: settledSite !== "" && settledEnvironment !== "",
  });

  // The turns of the order come over the stream: the host redeeming the
  // token, a refusal, a revocation. The poll stays as the fallback and
  // slows down while the stream is open - the steps after the token (the
  // session, the inventory) are gates the panel watches on its own, and
  // they still come in with the poll.
  const live = useEnrollmentStream(created?.id ?? null, [["enrollment-request", created?.id]]);

  // The installation progress refreshes itself as long as something can
  // still change: until the host is ready or the order is closed.
  const progress = useQuery({
    queryKey: ["enrollment-request", created?.id],
    queryFn: () => api.get<EnrollmentOrder>(`/api/v1/enrollment-requests/${created?.id}`),
    enabled: !!created,
    refetchInterval: (query) => {
      const order = query.state.data;
      const pace = live.connected ? 10000 : 3000;
      if (!order) return pace;
      if (hostReady(order)) return false;
      return order.status === "pending" || order.status === "enrolled" ? pace : false;
    },
  });
  const state = progress.data ?? created;
  const steps = state?.steps ?? [];
  const ready = hostReady(state);

  // The token has a deadline and the screen counts it down.
  useEffect(() => {
    if (!created) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [created]);

  // A ready host has a workspace; the screen goes there on its own, with
  // the button as the fallback for a browser that blocks the redirect.
  useEffect(() => {
    if (ready && state?.enrolled_host_id && state.kind === "agent") {
      const timer = window.setTimeout(
        () => navigate(`/hosts/${state.enrolled_host_id}/overview`), 1500);
      return () => window.clearTimeout(timer);
    }
  }, [ready, state?.enrolled_host_id, state?.kind, navigate]);

  const orderBody = () => ({
    description,
    site,
    environment,
    kind,
    purpose: kind === "relay" ? "relay" : "new",
    relay_id: kind === "agent" && route === "relay" ? relayId : "",
    owner: owner.trim(),
    tags: tags.split(/\s+/).map((tag) => tag.trim()).filter(Boolean),
    max_uses: maxUses,
    ttl_minutes: minutes,
    reason,
  });

  const failed = (error: unknown) => {
    if (error instanceof ApiError) {
      setRefusal(error);
      setMessage("");
      return;
    }
    setMessage(error instanceof Error ? error.message : String(error));
  };

  const order = useMutation({
    mutationFn: () => api.post<NewOrder>("/api/v1/enrollment-requests", orderBody()),
    onSuccess: (result) => {
      setCreated(result);
      setCopied("");
      setMessage("");
      setRefusal(null);
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: failed,
  });

  // Regenerate first revokes the order in hand, then places another: two
  // live tokens for one host would be one too many.
  const regenerate = useMutation({
    mutationFn: async (previous: string) => {
      await api.post(`/api/v1/enrollment-requests/${previous}/revoke`, {});
      return api.post<NewOrder>("/api/v1/enrollment-requests", orderBody());
    },
    onSuccess: (result) => {
      setCreated(result);
      setCopied("");
      setMessage(t("The previous order was revoked; this is the new token."));
      setRefusal(null);
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: failed,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/enrollment-requests/${id}/revoke`, {}),
    onSuccess: (_result, id) => {
      setMessage(t("Enrollment request revoked; the token no longer works."));
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
      if (created?.id === id) {
        queryClient.invalidateQueries({ queryKey: ["enrollment-request", id] });
      }
    },
    onError: failed,
  });

  if (list.error) return <ErrorBox error={list.error} />;

  const copy = (label: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(label);
  };

  // A reason is required where the API will refuse without one: a
  // production environment, a batch token or a relay.
  const reasonRequired = !!profile.data?.reason_required || maxUses > 1 || kind === "relay";
  const reasonGiven = reason.trim().length >= 8;
  const gates: { open: boolean; reason: string }[] = [
    { open: true, reason: "" },
    {
      open: site.trim() !== "" && environment.trim() !== "" && (!reasonRequired || reasonGiven),
      reason: site.trim() === "" || environment.trim() === ""
        ? t("site and environment first")
        : t("a reason first"),
    },
    { open: kind === "relay" || route === "direct" || relayId !== "", reason: t("choose the route") },
    { open: FAMILIES.some((entry) => entry.key === family), reason: t("choose the system") },
    { open: !!created, reason: t("place the order first") },
  ];
  const open = (index: number) => gates.slice(0, index).every((gate) => gate.open);
  const blocker = (index: number) => gates.slice(0, index).find((gate) => !gate.open)?.reason;

  const currentFamily = profile.data?.families.find((entry) => entry.key === family);
  const pending = (list.data?.items ?? []).filter((entry) => entry.status === "pending");
  const expired = created ? new Date(created.expires_at).getTime() <= now : false;
  const currentStatus = state?.status ?? "pending";
  const active = currentStatus === "pending" && !expired;

  return (
    <>
      <PageHeader
        title={t("Add host")}
        breadcrumb={[{ label: t("Hosts"), to: "/hosts" }]}
        description={t("A host joins the fleet by proving it holds a one-time token, then keeping the certificate the panel issues for it. The token is shown once, here, and never again — it is not stored in this browser and cannot be read back from the panel.")}
      />

      <ol className="bulk-steps">
        {STEPS.map((title, index) => (
          <li key={title}>
            {/* The decisions before the order are settled by it: a token
                for one placement does not move to another. A new order
                starts over. */}
            <button
              className={index === step ? "step active" : "step"}
              onClick={() => setStep(index)}
              disabled={!open(index) || (!!created && index < 4)}
            >
              <span className="number">{index + 1}</span>
              <span className="title">{t(title)}</span>
              {!open(index) && <span className="reason">{blocker(index)}</span>}
            </button>
          </li>
        ))}
      </ol>

      {step === 0 && (
        <Card
          title={t("1. What is being installed")}
          description={t("An agent manages one host. A relay carries the traffic of a site the panel cannot reach directly - it is a separate trust boundary with its own permission and its own certificate kind.")}
          footer={<Actions><button onClick={() => setStep(1)}>{t("Continue")}</button></Actions>}
        >
          <div className="segmented" role="group">
            <button className={kind === "agent" ? "active" : ""} onClick={() => setKind("agent")}>
              {t("Agent")}
            </button>
            {canEnrollRelay && (
              <button className={kind === "relay" ? "active" : ""} onClick={() => setKind("relay")}>
                {t("Relay")}
              </button>
            )}
          </div>
          {!canEnrollRelay && (
            <p className="source">{t("Registering a relay requires the relay.enroll.create permission.")}</p>
          )}
        </Card>
      )}

      {step === 1 && (
        <Card
          title={t("2. Where the host belongs")}
          description={t("The site and the environment decide who may manage the host and which policies apply to it. They come from the order, not from a file on the host.")}
          footer={
            <Actions>
              <button onClick={() => setStep(2)} disabled={!gates[1].open}>{t("Continue")}</button>
              <button className="secondary" onClick={() => setStep(0)}>{t("Back")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("What this host is for")} wide>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={t("web-042, Warsaw production")}
              />
            </Field>
            {/* The sites and environments the fleet already has are offered
                under the inputs, so a new host lands in "warsaw" and not in
                a "Warsaw" of its own; a name nobody used yet still goes
                through - the first host of a site has to come from somewhere. */}
            <Field label={t("Site")}>
              <input value={site} onChange={(e) => setSite(e.target.value)} list="add-host-sites" />
              <FacetList id="add-host-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")}>
              <input value={environment} onChange={(e) => setEnvironment(e.target.value)} list="add-host-environments" />
              <FacetList id="add-host-environments" facets={facets.data?.by_environment} />
            </Field>
            {/* The owner and the tags are optional here and editable on
                the host later; given now, the host needs no second visit
                once it appears. The tags have the shape the tag editor
                accepts, and the server refuses the order otherwise. */}
            <Field label={t("Owner")} hint={t("Who answers for the host; a person or a team. Optional.")}>
              <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder={t("platform team")} maxLength={128} />
            </Field>
            <Field label={t("Tags")} hint={t("Separated by spaces, key or key=value; added to the host at enrollment. Optional.")}>
              <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="role=web tier=gold" />
            </Field>
            {/* A batch token admits several machines; the reason it asks
                for is the same one the audit trail keeps. The field is
                for holders of host.enroll.batch: everyone else orders a
                token per host, which the document prefers anyway. */}
            {canEnrollBatch ? (
              <Field
                label={t("Uses")}
                hint={t("1 for one host; more for a batch of identical machines, with a reason.")}
              >
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={maxUses}
                  onChange={(e) => setMaxUses(Math.max(1, Number(e.target.value)))}
                />
              </Field>
            ) : (
              <Field label={t("Uses")} hint={t("One host per token. A token for a batch of machines needs the host.enroll.batch permission.")}>
                <input type="number" value={1} disabled />
              </Field>
            )}
            {/* A short deadline is a safeguard, not an inconvenience: a token
                that lies around for hours is a secret waiting to leak. */}
            <Field label={t("Token valid for (minutes, at most 24 h)")}>
              <input
                type="number"
                min={1}
                max={1440}
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </Field>
            {reasonRequired && (
              <Field
                label={t("Reason")}
                wide
                hint={t("Required here: a production environment, a batch token or a relay is a change the audit trail keeps the reason of. At least 8 characters.")}
              >
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={t("change ticket, purpose of the machine")}
                />
              </Field>
            )}
          </FieldGrid>
        </Card>
      )}

      {step === 2 && (
        <Card
          title={t("3. How the host connects")}
          description={kind === "relay"
            ? t("A relay connects to the panel directly: it is the route for the hosts of its site, not a host behind another relay.")
            : t("A host in a site with a relay connects through it; the order is then bound to that relay and its token works nowhere else. Without a relay the host reaches the panel under its advertised addresses.")}
          footer={
            <Actions>
              <button onClick={() => setStep(3)} disabled={!gates[2].open}>{t("Continue")}</button>
              <button className="secondary" onClick={() => setStep(1)}>{t("Back")}</button>
            </Actions>
          }
        >
          {kind === "agent" && (
            <>
              <div className="segmented" role="group">
                <button className={route === "direct" ? "active" : ""} onClick={() => setRoute("direct")}>
                  {t("Directly to the panel")}
                </button>
                <button
                  className={route === "relay" ? "active" : ""}
                  onClick={() => setRoute("relay")}
                  disabled={usableRelays.length === 0}
                >
                  {t("Through a relay of the site")}
                </button>
              </div>
              {relays.error && <ErrorBox error={relays.error} />}
              {usableRelays.length === 0 && !relays.isPending && (
                <p className="source">{t("Site {site} has no relay; the host connects directly.", { site })}</p>
              )}
              {route === "relay" && (
                <FieldGrid>
                  <Field label={t("Relay")} wide>
                    <select value={relayId} onChange={(e) => setRelayId(e.target.value)}>
                      <option value="">{t("choose a relay")}</option>
                      {usableRelays.map((relay) => (
                        <option key={relay.id} value={relay.id}>
                          {relay.name}
                          {relay.environment ? ` (${relay.environment})` : ""}
                        </option>
                      ))}
                    </select>
                  </Field>
                </FieldGrid>
              )}
              {route === "relay" && relayId && (
                <p className="source">
                  {t("Last seen")}{" "}
                  <Time value={usableRelays.find((relay) => relay.id === relayId)?.last_seen_at} />
                </p>
              )}
            </>
          )}
          {profile.data && (
            <p className="source">
              {t("Enrollment")}: <code>{profile.data.connection.enrollment_url}</code>
              {" · "}
              {t("Gateways")}: <code>{profile.data.connection.gateway_urls.join(", ")}</code>
            </p>
          )}
          {profile.error && <ErrorBox error={profile.error} />}
        </Card>
      )}

      {step === 3 && (
        <Card
          title={t("4. Which system")}
          description={t("The family picks the repository and the package manager; the architecture picks the artefact. The channel is stable.")}
          footer={
            <Actions>
              <button onClick={() => setStep(4)} disabled={!gates[3].open}>{t("Continue")}</button>
              <button className="secondary" onClick={() => setStep(2)}>{t("Back")}</button>
            </Actions>
          }
        >
          {/* The commands differ by package manager; the choice changes
              nothing on the server. */}
          <div className="segmented" role="group">
            {FAMILIES.map((entry) => (
              <button
                key={entry.key}
                className={family === entry.key ? "active" : ""}
                onClick={() => setFamily(entry.key)}
              >
                {entry.label}
              </button>
            ))}
          </div>
          <FieldGrid>
            <Field label={t("Architecture")}>
              <select value={architecture} onChange={(e) => setArchitecture(e.target.value)}>
                {(profile.data?.architectures ?? ["amd64", "arm64"]).map((entry) => (
                  <option key={entry} value={entry}>{entry}</option>
                ))}
              </select>
            </Field>
            <Field label={t("Channel")}>
              <input value={profile.data?.channel ?? "stable"} readOnly />
            </Field>
          </FieldGrid>
          {profile.data?.warnings?.map((warning) => (
            <p key={warning} className="source">{warning}</p>
          ))}
        </Card>
      )}

      {step === 4 && !created && (
        <Card
          title={t("5. Place the order")}
          description={t("The order creates the token for {kind} in site {site}, environment {environment}. The token is shown once, right after.", { kind: t(kind === "relay" ? "a relay" : "an agent"), site, environment })}
          footer={
            <Actions>
              <button onClick={() => order.mutate()} disabled={order.isPending}>
                {t("Create enrollment token")}
              </button>
              <button className="secondary" onClick={() => setStep(3)}>{t("Back")}</button>
            </Actions>
          }
        >
          {refusal && <Refusal error={refusal} close={() => setRefusal(null)} />}
          {refusal?.code === "reason_required" && !reasonRequired && (
            <FieldGrid>
              <Field label={t("Reason")} wide>
                <input value={reason} onChange={(e) => setReason(e.target.value)} />
              </Field>
            </FieldGrid>
          )}
        </Card>
      )}

      {step === 4 && created && (
        <>
          <Card
            title={t("5. Install on the host")}
            description={
              <>
                {t("Site {site} · environment {environment} · token expires", { site: created.site, environment: created.environment })}{" "}
                <Time value={created.expires_at} />
                {active && <> ({timeLeft(created.expires_at, now)})</>}
                {expired && currentStatus === "pending" && <> · {t("expired")}</>}
                {currentStatus !== "pending" && <> · {t(currentStatus)}</>}
              </>
            }
            footer={
              <Actions>
                <button onClick={() => setStep(5)}>{t("Continue to the status")}</button>
                <button
                  className="secondary"
                  onClick={() => regenerate.mutate(created.id)}
                  disabled={regenerate.isPending}
                >
                  {t("Regenerate")}
                </button>
                <button
                  className="secondary"
                  onClick={() => revoke.mutate(created.id)}
                  disabled={!active || revoke.isPending}
                >
                  {t("Revoke token")}
                </button>
              </Actions>
            }
          >
            <Actions>
              <button onClick={() => copy("token", created.token)} disabled={!active}>
                {copied === "token" ? t("Token copied") : t("Copy token")}
              </button>
              <span className="source">
                {t("Shown once. Paste it into the hidden prompt on the host; do not put it in a shell command — the command line is visible to every user of that machine.")}
              </span>
            </Actions>
            {refusal && <Refusal error={refusal} close={() => setRefusal(null)} />}
          </Card>

          <Columns wide>
            <Card
              title={t("Installation on {family}", { family: currentFamily?.label ?? FAMILIES.find((entry) => entry.key === family)?.label ?? family })}
              description={profile.data && !profile.data.repository.configured
                ? t("No package repository is configured on the panel; replace {url} in the commands with the address of yours.", { url: profile.data.repository.url })
                : undefined}
            >
              {profile.error && <ErrorBox error={profile.error} />}
              {!currentFamily && !profile.error && <Empty>{t("waiting for the installation profile…")}</Empty>}
              {currentFamily && (
                <ol className="steps">
                  {currentFamily.steps.map((command) => (
                    <li key={command.key}>
                      {t(commandTitles[command.key])}
                      {command.key === "config" && <> <code>{profile.data?.config.path}</code></>}
                      {command.key === "ca" && <> <code>{profile.data?.ca.path}</code></>}
                      <pre>{command.command}</pre>
                      <button className="secondary" onClick={() => copy(command.key, command.command)}>
                        {copied === command.key ? t("Copied") : t("Copy command")}
                      </button>
                    </li>
                  ))}
                </ol>
              )}
            </Card>

            {profile.data && (
              <Card
                title={t("Files")}
                description={t("The same content the commands carry, for a host set up by other means. The configuration can also be fetched from the panel with the right to read installations.")}
              >
                <p>
                  <strong>{profile.data.config.path}</strong>{" "}
                  <span className="source"><code>{created.config_url}</code></span>
                </p>
                <pre>{profile.data.config.content}</pre>
                <Actions>
                  <button className="secondary" onClick={() => copy("config-file", profile.data!.config.content)}>
                    {copied === "config-file" ? t("Copied") : t("Copy configuration")}
                  </button>
                </Actions>
                <p>
                  <strong>{profile.data.ca.path}</strong>{" "}
                  <span className="source">{profile.data.ca.subject} · {t("valid until")} <Time value={profile.data.ca.not_after} /></span>
                </p>
                <pre>{profile.data.ca.pem}</pre>
                <p className="source">
                  {t("SHA-256 fingerprint of the signing CA; compare it with what openssl prints on the host.")}
                </p>
                <pre>{profile.data.ca.fingerprint_sha256}</pre>
                <Actions>
                  <button className="secondary" onClick={() => copy("ca-file", profile.data!.ca.pem)}>
                    {copied === "ca-file" ? t("Copied") : t("Copy CA")}
                  </button>
                  <button className="secondary" onClick={() => copy("fingerprint", profile.data!.ca.fingerprint_sha256)}>
                    {copied === "fingerprint" ? t("Copied") : t("Copy fingerprint")}
                  </button>
                </Actions>
              </Card>
            )}
          </Columns>
        </>
      )}

      {step === 5 && created && (
        <Card
          title={t("6. Enrollment status")}
          description={ready
            ? t("The host is ready: the session is up, the capabilities are known and the first inventory has arrived. Opening its workspace.")
            : t("What the host has done so far, as the panel sees it - not as the agent declares it. A stopped step names its reason when the panel knows one.")}
          footer={
            <Actions>
              {state?.enrolled_host_id && state.kind === "agent" && (
                <button onClick={() => navigate(`/hosts/${state.enrolled_host_id}/overview`)}>
                  {t("Open host")}
                </button>
              )}
              <button className="secondary" onClick={() => setStep(4)}>{t("Back to the installation")}</button>
              <button className="secondary" onClick={() => revoke.mutate(created.id)} disabled={!active}>
                {t("Revoke token")}
              </button>
              <button
                className="secondary"
                onClick={() => {
                  setCreated(null);
                  setStep(0);
                  setMessage("");
                }}
              >
                {t("Add another host")}
              </button>
            </Actions>
          }
        >
          {progress.error && <ErrorBox error={progress.error} />}
          <ul className="steps" aria-live="polite">
            {steps.map((entry) => (
              <li key={entry.key}>
                <span className={`badge ${entry.state === "done" ? "ok" : entry.state === "failed" ? "error" : entry.error_code ? "warn" : "unknown"}`}>
                  {stepMark(entry.state)}
                </span>{" "}
                {t(stepDescriptions[entry.key])}
                {entry.error_code && (
                  <div className="source">
                    <code>{entry.error_code}</code>{" "}
                    {errorDescriptions[entry.error_code]
                      ? t(errorDescriptions[entry.error_code])
                      : entry.detail}
                  </div>
                )}
              </li>
            ))}
            {!steps.length && <li className="source">{t("waiting for the host…")}</li>}
          </ul>
          {/* Where the news comes from: the stream announces the host the
              moment it redeems the token; without it the screen asks every
              few seconds, which is slower but says the same. */}
          {!ready && (
            <p className="source">
              {live.connected
                ? t("Watching the order live; a refusal or the host's arrival shows at once.")
                : t("Refreshing every few seconds.")}
            </p>
          )}
        </Card>
      )}

      {message && <p className="source">{message}</p>}

      <Card title={t("Pending installations")} flush>
        {!pending.length ? (
          <Empty>{t("No installation is waiting for a host right now.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("What for")}</th><th>{t("Scope")}</th><th className="num">{t("Uses")}</th><th>{t("Expires")}</th><th>{t("Requested by")}</th><th></th>
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
                  <td className="num">{entry.uses} / {entry.max_uses}</td>
                  <td className="source"><Time value={entry.expires_at} /></td>
                  <td className="source">{entry.created_by}</td>
                  <td className="actions-cell">
                    <div className="row-actions">
                      <button className="secondary" onClick={() => revoke.mutate(entry.id)}>
                        {t("Revoke")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

/**
 * A refusal of the order that the operator can do something about: a
 * missing reason is a field to fill in, a stale authentication is a sign-in
 * that comes back to the same place. Anything else is shown as it came.
 */
function Refusal({ error, close }: { error: ApiError; close: () => void }) {
  const t = useT();
  if (error.code === "reauthentication_required") {
    return (
      <div className="warning">
        <div>
          <strong>{t("Re-authentication required.")}</strong> {error.message}
        </div>
        <div className="operations">
          <button
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </button>
          <button className="secondary" onClick={close}>{t("Close")}</button>
        </div>
      </div>
    );
  }
  return (
    <div className="warning">
      <div>
        {error.code === "reason_required"
          ? t("The order needs a reason: this placement, a batch token or a relay is a change the audit trail keeps the reason of.")
          : error.message}
      </div>
      <div className="operations"><button className="secondary" onClick={close}>{t("Close")}</button></div>
    </div>
  );
}
