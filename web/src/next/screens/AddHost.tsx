import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { copyToClipboard } from "../../lib/clipboard";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, relativeTime } from "../../lib/format";
import { useEnrollmentStream } from "../../lib/stream";
import type {
  EnrollmentOrder, EnrollmentStep, EnrollmentStepState, Facet, FleetActivity,
  InstallationCommand, InstallationFamily, InstallationProfile, Relay, Whoami,
} from "../../lib/types";
import { useT, type Translate } from "../../i18n";
import {
  Actions, Banner, Bones, Card, Download, Fact, Facts, Field, Fields,
  Note, Pill, Problem, Screen, Seg, Table, type Tone,
} from "../kit";

/**
 * How a host joins the fleet.
 *
 * This is the first screen a new operator ever uses, so it is written as
 * instructions and not as a form: five numbered cards in the order the
 * decisions are actually made, then the commands to run on the machine,
 * then what the panel has seen the machine do. Nothing is hidden behind a
 * step somebody has to guess their way into.
 *
 * The token exists for one moment - the answer that placed the order -
 * and it is never drawn on the screen, never put in an address and never
 * written to the console. It leaves this page by the clipboard alone, and
 * the sentence beside the button says why it must not go on a command
 * line: argv is readable by every user of that machine.
 */

/** The order right after creation - the only moment the token exists. */
type NewOrder = EnrollmentOrder & { token: string };

/** The distribution families the release packages; the keys match the profile. */
const FAMILIES = [
  { key: "debian", label: "Debian" },
  { key: "ubuntu", label: "Ubuntu" },
  { key: "rhel", label: "RHEL / Fedora" },
  { key: "arch", label: "Arch Linux" },
];

/** How short a reason the audit trail will take. */
export const ENROLLMENT_REASON_MIN_LENGTH = 8;

/**
 * The installation step in the operator's language.
 *
 * It is a function of literals rather than a table of them so that the
 * catalogue check sees every sentence the screen can say.
 */
export function stepName(key: EnrollmentStep["key"], t: Translate): string {
  switch (key) {
    case "token": return t("token accepted");
    case "certificate": return t("certificate issued");
    case "connected": return t("agent online");
    case "inventory": return t("inventory received");
  }
}

/** What each command does, by the stable key the profile names it with. */
export function commandTitle(key: InstallationCommand["key"], t: Translate): string {
  switch (key) {
    case "repository": return t("Add the signed repository");
    case "package": return t("Install the agent package");
    case "image": return t("Pull the relay image, pinned by digest");
    case "config": return t("Save the configuration");
    case "ca": return t("Save the fleet CA and compare the fingerprint");
    case "pin": return t("Name this panel, before the host trusts any");
    case "enroll": return t("Register the host and paste the token when asked");
    case "start": return t("Start the agent");
  }
}

/** What an error code the panel knows means for the person at the screen. */
export function errorMeaning(code: string, t: Translate): string | undefined {
  switch (code) {
    case "token_expired":
      return t("The token expired before the host used it. Regenerate the order and try again.");
    case "token_revoked":
      return t("The order was revoked; its token no longer works.");
    case "enrollment_request_reused":
      return t("The order was already used up. Another host needs another order.");
    case "machine_id_mismatch":
      return t("The machine is not the one the order was bound to.");
    case "relay_scope_mismatch":
      return t("The host came by a route the order does not allow: directly instead of through the relay, or through the relay of another site.");
    case "duplicate_machine_id":
      return t("The machine is already in the fleet under another host; a new-host token does not fit it. Use identity recovery on that host instead.");
    case "csr_invalid":
      return t("The certificate request from the host was refused. Check the agent journal on the host.");
    case "host_retired":
      return t("The host was decommissioned and does not come back with a token.");
    case "machine_id_retired":
      return t("The machine belongs to a retired host and is held back for the retention period; a new-host token does not fit it yet.");
    case "enrolled_not_connected":
      return t("The certificate was issued, but no session has opened. Check that the service runs and that the gateway address is reachable from the host.");
    case "inventory_unavailable":
      return t("The agent is connected, but no inventory has arrived. Check the agent journal for a module that fails to read the host.");
    default:
      return undefined;
  }
}

/** The status of an order in one word the catalogue knows. */
export function statusWord(status: EnrollmentOrder["status"], t: Translate): string {
  switch (status) {
    case "pending": return t("pending");
    case "enrolled": return t("enrolled");
    case "expired": return t("expired");
    case "revoked": return t("revoked");
    case "failed": return t("failed");
  }
}

/** How an order's status reads as a state. */
export function statusTone(status: EnrollmentOrder["status"]): Tone {
  if (status === "pending") return "ok";
  if (status === "enrolled") return "info";
  if (status === "failed") return "error";
  return "unknown";
}

/** How a step reads as a state: a stopped step that says why is a warning. */
export function stepTone(step: EnrollmentStep): Tone {
  if (step.state === "done") return "ok";
  if (step.state === "failed") return "error";
  return step.error_code ? "warn" : "unknown";
}

/** The step state said in a word; colour alone is not a state. */
export function stepWord(state: EnrollmentStepState, t: Translate): string {
  if (state === "done") return t("done");
  if (state === "failed") return t("stopped");
  return t("waiting");
}

/** A host is ready when every stage is done: session, capabilities, inventory. */
export function hostReady(order?: EnrollmentOrder | null): boolean {
  return !!order?.enrolled_host_id && !!order.steps?.length &&
    order.steps.every((step) => step.state === "done");
}

/** The time left on a token, as minutes and seconds; 0:00 once it has passed. */
export function timeLeft(expiresAt: string, now: number): string {
  const left = Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000));
  return `${Math.floor(left / 60)}:${(left % 60).toString().padStart(2, "0")}`;
}

/** The values the fleet already uses, offered under an input that still takes any word. */
function Known({ id, facets }: { id: string; facets?: Facet[] }) {
  return (
    <datalist id={id}>
      {(facets ?? []).map((facet) => <option key={facet.key} value={facet.key} label={`${facet.count}`} />)}
    </datalist>
  );
}

export function AddHost() {
  const t = useT();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [kind, setKind] = useState<"agent" | "relay">("agent");
  const [description, setDescription] = useState("");
  const [site, setSite] = useState("default");
  const [environment, setEnvironment] = useState("unassigned");
  const [reason, setReason] = useState("");
  // What the operator already knows about the machine: it goes onto the host
  // the moment it enrolls, so a host that appears at night appears as
  // somebody's and inside the campaigns its tags select.
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
  const [uncopied, setUncopied] = useState("");
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
  // A token for many machines is a separate right on top of inviting one;
  // without it the field is not offered, so the order is not refused after
  // the form has been filled in.
  const canEnrollBatch = permissions.includes("host.enroll.batch");

  // The history of orders within the operator's scope - the server keeps out
  // what lies elsewhere - narrowed by status on request.
  const [historyStatus, setHistoryStatus] = useState<EnrollmentOrder["status"] | "">("pending");
  const list = useQuery({
    queryKey: ["enrollment-requests", historyStatus],
    queryFn: () => api.get<{ items: EnrollmentOrder[] }>(
      `/api/v1/enrollment-requests?limit=100${historyStatus ? `&status=${historyStatus}` : ""}`),
  });

  // The placement the fleet already has, offered under the inputs.
  const facets = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    staleTime: 60_000,
  });
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

  // The profile for the placement: it says whether the order needs a reason,
  // and carries the configuration, the trust and the commands.
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
  // token, a refusal, a revocation.
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

  // A route through a relay cannot be held once the site has none; without
  // this the order would carry a relay the chosen site never had.
  useEffect(() => {
    if (route === "relay" && kind === "agent" && !relays.isPending && usableRelays.length === 0) {
      setRoute("direct");
      setRelayId("");
    }
  }, [route, kind, relays.isPending, usableRelays.length]);

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
      setUncopied("");
      setMessage("");
      setRefusal(null);
      void queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: failed,
  });

  // The screen takes the shape of an order: the placement, the route, the
  // owner and the tags, so the installation commands and a further
  // regeneration follow the order in hand rather than the last form.
  const adopt = (shape: EnrollmentOrder) => {
    setKind(shape.kind);
    setDescription(shape.description ?? "");
    setSite(shape.site);
    setEnvironment(shape.environment);
    setOwner(shape.owner ?? "");
    setTags((shape.tags ?? []).join(" "));
    setMaxUses(shape.max_uses);
    setMinutes(Math.max(1, Math.round(
      (new Date(shape.expires_at).getTime() - new Date(shape.created_at).getTime()) / 60000)));
    setRoute(shape.relay_id ? "relay" : "direct");
    setRelayId(shape.relay_id ?? "");
  };

  // Regenerate is the same replacement the history offers: the server revokes
  // the order in hand and places one like it, so two live tokens never coexist.
  const replace = useMutation({
    mutationFn: (previous: EnrollmentOrder) =>
      api.post<NewOrder>(`/api/v1/enrollment-requests/${previous.id}/replace`, { reason }),
    onSuccess: (result, previous) => {
      adopt(result);
      setCreated(result);
      setCopied("");
      setUncopied("");
      setMessage(previous.status === "pending"
        ? t("The previous order was revoked; this is the new token.")
        : t("A similar order was placed; this is its token."));
      setRefusal(null);
      void queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: failed,
  });
  const regenerate = (id: string) => {
    const previous = created?.id === id
      ? (state ?? created)
      : list.data?.items.find((entry) => entry.id === id);
    if (previous) replace.mutate(previous);
  };

  const revoke = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/enrollment-requests/${id}/revoke`, {}),
    onSuccess: (_result, id) => {
      setMessage(t("Enrollment request revoked; the token no longer works."));
      void queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
      if (created?.id === id) {
        void queryClient.invalidateQueries({ queryKey: ["enrollment-request", id] });
      }
    },
    onError: failed,
  });

  const copy = (label: string, text: string) => {
    void copyToClipboard(text).then((done) => {
      setCopied(done ? label : "");
      setUncopied(done ? "" : label);
    });
  };

  // A reason is required where the API will refuse without one: a
  // production environment, a batch token or a relay.
  const reasonRequired = !!profile.data?.reason_required || maxUses > 1 || kind === "relay";
  const reasonGiven = reason.trim().length >= ENROLLMENT_REASON_MIN_LENGTH;
  // A relay comes back with one family - a container one - so there is nothing
  // to pick and the package manager chosen for an agent does not apply.
  const offered: InstallationFamily[] = profile.data?.families ?? [];
  const singleFamily = offered.length === 1;
  const currentFamily = singleFamily ? offered[0] : offered.find((entry) => entry.key === family);
  // Without a release manifest the control plane cannot name the image, and a
  // step with no reference is not offered as a command.
  const imageUnknown = !!profile.data && !profile.data.image.known;

  const gates = [
    {
      open: site.trim() !== "" && environment.trim() !== "",
      reason: t("site and environment first"),
    },
    { open: !reasonRequired || reasonGiven, reason: t("a reason first") },
    {
      open: kind === "relay" || route === "direct" || relayId !== "",
      reason: t("choose the route"),
    },
    {
      open: singleFamily || FAMILIES.some((entry) => entry.key === family),
      reason: t("choose the system"),
    },
  ];
  const blocker = gates.find((gate) => !gate.open)?.reason;

  // The options are typed on the whole choice and not on what happens to be
  // offered: a segment with one option still belongs to a two-valued choice.
  const kindOptions: { value: "agent" | "relay"; label: string }[] = canEnrollRelay
    ? [{ value: "agent", label: t("Agent") }, { value: "relay", label: t("Relay") }]
    : [{ value: "agent", label: t("Agent") }];
  const routeOptions: { value: "direct" | "relay"; label: string }[] = usableRelays.length > 0
    ? [
      { value: "direct", label: t("Directly to the panel") },
      { value: "relay", label: t("Through a relay of the site") },
    ]
    : [{ value: "direct", label: t("Directly to the panel") }];

  const orders = list.data?.items ?? [];
  const expired = created ? new Date(created.expires_at).getTime() <= now : false;
  const currentStatus = state?.status ?? "pending";
  const active = currentStatus === "pending" && !expired;
  const chosenRelay = usableRelays.find((relay) => relay.id === relayId);

  const banner = created && ready
    ? (
      <Banner tone="ok">
        {t("The host is ready: the session is up, the capabilities are known and the first inventory has arrived. Opening its workspace.")}
      </Banner>
    )
    : created
      ? (
        <Banner tone={active ? "info" : "warn"}>
          {active
            ? t("A token is live for site {site}, environment {environment}. It expires in {left}.",
                { site: created.site, environment: created.environment, left: timeLeft(created.expires_at, now) })
            : expired && currentStatus === "pending"
              ? t("The token expired before a host used it. Regenerate the order to get another.")
              : t("This order is {status}; its token no longer admits a host.",
                  { status: statusWord(currentStatus, t) })}
        </Banner>
      )
      : undefined;

  return (
    <Screen
      icon="add-host"
      title={t("Add a host")}
      lead={t("How a host joins the fleet, and the token that lets it.")}
      help={
        <p>
          {t("A host joins the fleet by proving it holds a one-time token, then keeping the certificate the panel issues for it. The token is shown once, here, and never again — it is not stored in this browser and cannot be read back from the panel. Work down the cards in order: what is being installed, where it belongs, how it reaches the panel and which system it runs; then place the order, run the commands on the machine, and watch what the panel sees the machine do.")}
        </p>
      }
      banner={banner}
      actions={created && (
        <button
          type="button"
          onClick={() => { setCreated(null); setMessage(""); setRefusal(null); setCopied(""); setUncopied(""); }}
          data-testid="add-another"
        >
          {t("Add another host")}
        </button>
      )}
    >
      {refusal && <Refusal error={refusal} close={() => setRefusal(null)} />}
      {message && <Note>{message}</Note>}

      {!created && (
        <>
          <Card
            title={t("1. What is being installed")}
            note={t("An agent manages one host. A relay carries the traffic of a site the panel cannot reach directly — it is a separate trust boundary with its own permission and its own certificate kind.")}
          >
            <Seg
              label={t("What is being installed")}
              value={kind}
              onChange={setKind}
              options={kindOptions}
            />
            {!canEnrollRelay && (
              <Note>{t("Registering a relay requires the relay.enroll.create permission.")}</Note>
            )}
          </Card>

          <Card
            title={t("2. Where the host belongs")}
            note={t("The site and the environment decide who may manage the host and which policies apply to it. They come from the order, not from a file on the host.")}
          >
            <Fields>
              <Field label={t("What this host is for")} wide>
                <input
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                  placeholder={t("web-042, Warsaw production")}
                  data-testid="description"
                />
              </Field>
              {/* The sites and environments the fleet already has are offered
                  under the inputs, so a new host lands in "warsaw" and not in
                  a "Warsaw" of its own; a name nobody used yet still goes
                  through - the first host of a site has to come from somewhere. */}
              <Field label={t("Site")}>
                <input
                  value={site}
                  onChange={(event) => setSite(event.target.value)}
                  list="add-host-sites"
                  data-testid="site"
                />
                <Known id="add-host-sites" facets={facets.data?.by_site} />
              </Field>
              <Field label={t("Environment")}>
                <input
                  value={environment}
                  onChange={(event) => setEnvironment(event.target.value)}
                  list="add-host-environments"
                  data-testid="environment"
                />
                <Known id="add-host-environments" facets={facets.data?.by_environment} />
              </Field>
              {/* The owner and the tags are optional here and editable on the
                  host later; given now, the host needs no second visit once it
                  appears. The tags have the shape the tag editor accepts, and
                  the server refuses the order otherwise. */}
              <Field label={t("Owner")} hint={t("Who answers for the host; a person or a team. Optional.")}>
                <input
                  value={owner}
                  onChange={(event) => setOwner(event.target.value)}
                  placeholder={t("platform team")}
                  maxLength={128}
                  data-testid="owner"
                />
              </Field>
              <Field
                label={t("Tags")}
                hint={t("Separated by spaces, key or key=value; added to the host at enrollment. Optional.")}
              >
                <input
                  value={tags}
                  onChange={(event) => setTags(event.target.value)}
                  placeholder="role=web tier=gold"
                  data-testid="tags"
                />
              </Field>
              {/* A batch token admits several machines; the reason it asks for
                  is the same one the audit trail keeps. The field is for
                  holders of host.enroll.batch: everyone else orders a token
                  per host, which the document prefers anyway. */}
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
                    onChange={(event) => setMaxUses(Math.max(1, Number(event.target.value)))}
                    data-testid="uses"
                  />
                </Field>
              ) : (
                <Field
                  label={t("Uses")}
                  hint={t("One host per token. A token for a batch of machines needs the host.enroll.batch permission.")}
                >
                  <input type="number" value={1} disabled data-testid="uses" />
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
                  onChange={(event) => setMinutes(Number(event.target.value))}
                  data-testid="minutes"
                />
              </Field>
              {reasonRequired && (
                <Field
                  label={t("Reason (kept in the audit trail)")}
                  wide
                  hint={t("Required here: a production environment, a batch token or a relay is a change the audit trail keeps the reason of. At least {n} characters.", { n: ENROLLMENT_REASON_MIN_LENGTH })}
                >
                  <input
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder={t("change ticket, purpose of the machine")}
                    data-testid="reason"
                  />
                </Field>
              )}
            </Fields>
          </Card>

          <Card
            title={t("3. How the host connects")}
            note={kind === "relay"
              ? t("A relay connects to the panel directly: it is the route for the hosts of its site, not a host behind another relay.")
              : t("A host in a site with a relay connects through it; the order is then bound to that relay and its token works nowhere else. Without a relay the host reaches the panel under its advertised addresses.")}
          >
            {kind === "agent" && (
              <>
                <Seg
                  label={t("How the host connects")}
                  value={route}
                  onChange={setRoute}
                  options={routeOptions}
                />
                {relays.error && <Problem>{String(relays.error)}</Problem>}
                {usableRelays.length === 0 && !relays.isPending && (
                  <Note>{t("Site {site} has no relay; the host connects directly.", { site })}</Note>
                )}
                {route === "relay" && (
                  <Fields>
                    <Field
                      label={t("Relay")}
                      wide
                      hint={chosenRelay
                        ? t("Last seen {when}.", { when: relativeTime(chosenRelay.last_seen_at) })
                        : undefined}
                    >
                      <select
                        value={relayId}
                        onChange={(event) => setRelayId(event.target.value)}
                        data-testid="relay"
                      >
                        <option value="">{t("choose a relay")}</option>
                        {usableRelays.map((relay) => (
                          <option key={relay.id} value={relay.id}>
                            {relay.name}{relay.environment ? ` (${relay.environment})` : ""}
                          </option>
                        ))}
                      </select>
                    </Field>
                  </Fields>
                )}
              </>
            )}
            {profile.data && (
              <Facts>
                <Fact label={t("Enrollment")}><code>{profile.data.connection.enrollment_url}</code></Fact>
                <Fact label={t("Gateways")}><code>{profile.data.connection.gateway_urls.join(", ")}</code></Fact>
              </Facts>
            )}
            {profile.error && <Problem>{String(profile.error)}</Problem>}
          </Card>

          <Card
            title={t("4. Which system")}
            note={singleFamily
              ? t("This installation comes as a container image; only the architecture and the channel are left to pick. The channel is stable.")
              : t("The family picks the repository and the package manager; the architecture picks the artefact. The channel is stable.")}
          >
            {/* The commands differ by package manager; the choice changes
                nothing on the server. One family is not a choice, so it is named. */}
            {singleFamily ? (
              <Note>
                {t("Installed from an image, not from a package repository: {family}.", { family: offered[0].label })}
              </Note>
            ) : (
              <Seg
                label={t("Which system")}
                value={family}
                onChange={setFamily}
                options={FAMILIES.map((entry) => ({ value: entry.key, label: entry.label }))}
              />
            )}
            <Fields>
              <Field label={t("Architecture")}>
                <select
                  value={architecture}
                  onChange={(event) => setArchitecture(event.target.value)}
                  data-testid="architecture"
                >
                  {(profile.data?.architectures ?? ["amd64", "arm64"]).map((entry) => (
                    <option key={entry} value={entry}>{entry}</option>
                  ))}
                </select>
              </Field>
              <Field label={t("Channel")}>
                <input value={profile.data?.channel ?? "stable"} readOnly data-testid="channel" />
              </Field>
            </Fields>
            {profile.data?.warnings?.map((warning) => <Note key={warning}>{warning}</Note>)}
          </Card>

          <Card
            title={t("5. Place the order")}
            note={t("The order creates the token for {kind} in site {site}, environment {environment}. The token is shown once, right after.", {
              kind: kind === "relay" ? t("a relay") : t("an agent"),
              site,
              environment,
            })}
            foot={
              <Actions>
                <button
                  type="button"
                  onClick={() => order.mutate()}
                  disabled={order.isPending || !!blocker}
                  data-testid="place-order"
                >
                  {order.isPending ? t("Placing the order…") : t("Create enrollment token")}
                </button>
                {blocker && <Note>{t("Not yet: {what}.", { what: blocker })}</Note>}
              </Actions>
            }
          >
            {refusal?.code === "reason_required" && !reasonRequired && (
              <Fields>
                <Field label={t("Reason (kept in the audit trail)")} wide>
                  <input
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    data-testid="reason"
                  />
                </Field>
              </Fields>
            )}
          </Card>
        </>
      )}

      {created && (
        <>
          <Card
            title={t("5. The token")}
            note={t("Shown once. Paste it into the hidden prompt on the host; do not put it in a shell command — the command line is visible to every user of that machine.")}
            foot={
              <Actions>
                <button
                  type="button"
                  onClick={() => copy("token", created.token)}
                  disabled={!active}
                  data-testid="copy-token"
                >
                  {copied === "token" ? t("Token copied") : t("Copy token")}
                </button>
                <button
                  type="button"
                  onClick={() => regenerate(created.id)}
                  disabled={replace.isPending}
                  data-testid="regenerate"
                >
                  {replace.isPending ? t("Regenerating…") : t("Regenerate")}
                </button>
                <button
                  type="button"
                  onClick={() => revoke.mutate(created.id)}
                  disabled={!active || revoke.isPending}
                  data-testid="revoke-token"
                >
                  {t("Revoke token")}
                </button>
              </Actions>
            }
          >
            {uncopied === "token" && (
              <Problem>
                {t("The clipboard refused the token; this browser allows it only over HTTPS. Place the order again from a panel reached over HTTPS, or enroll the host from the command line.")}
              </Problem>
            )}
            <Facts>
              <Fact label={t("Site")}>{created.site}</Fact>
              <Fact label={t("Environment")}>{created.environment}</Fact>
              <Fact label={t("Uses")}>{`${state?.uses ?? created.uses} / ${created.max_uses}`}</Fact>
              <Fact label={t("Status")}>
                <Pill tone={statusTone(currentStatus)}>{statusWord(currentStatus, t)}</Pill>
              </Fact>
              <Fact label={t("Expires")}>
                <span title={absoluteTime(created.expires_at)}>
                  {active ? timeLeft(created.expires_at, now) : relativeTime(created.expires_at)}
                </span>
              </Fact>
            </Facts>
          </Card>

          <Card
            title={t("Install on {family}", {
              family: currentFamily?.label
                ?? FAMILIES.find((entry) => entry.key === family)?.label
                ?? family,
            })}
            note={profile.data && !profile.data.repository.configured
              && currentFamily?.steps.some((command) => command.key === "repository")
              ? t("No package repository is configured on the panel; replace {url} in the commands with the address of yours.", { url: profile.data.repository.url })
              : t("Run these on the machine, in this order.")}
          >
            {profile.error && <Problem>{String(profile.error)}</Problem>}
            {!currentFamily && !profile.error && <Bones rows={4} />}
            {imageUnknown && currentFamily?.steps.some((command) => command.key === "image") && (
              <Note>
                {t("This installation was given no release manifest, so the relay's image cannot be named here. The control plane supplies it from the file in FLOTESTRO_RELEASE_MANIFEST_FILE; until it has one, there is no digest to pull.")}
              </Note>
            )}
            {currentFamily && (
              <Fields>
                {currentFamily.steps.map((command, index) => (
                  <Field
                    key={command.key}
                    wide
                    label={`${index + 1}. ${commandTitle(command.key, t)}`}
                    hint={command.key === "config"
                      ? profile.data?.config.path
                      : command.key === "ca"
                        ? profile.data?.ca.path
                        : undefined}
                  >
                    {command.key === "image" && imageUnknown ? (
                      <Note>
                        {t("No image reference to copy: set FLOTESTRO_RELEASE_MANIFEST_FILE on the control plane and open this page again.")}
                      </Note>
                    ) : (
                      <>
                        <textarea
                          readOnly
                          value={command.command}
                          rows={Math.min(14, command.command.split("\n").length)}
                          aria-label={commandTitle(command.key, t)}
                          data-testid={`command-${command.key}`}
                        />
                        <Actions>
                          <button type="button" onClick={() => copy(command.key, command.command)}>
                            {copied === command.key ? t("Copied") : t("Copy command")}
                          </button>
                          {uncopied === command.key && (
                            <Note>{t("The clipboard refused it; select the text above and copy it by hand.")}</Note>
                          )}
                        </Actions>
                      </>
                    )}
                  </Field>
                ))}
              </Fields>
            )}
          </Card>

          {profile.data && (
            <Card
              title={t("Files")}
              note={t("The same content the commands carry, for a host set up by other means. The configuration can also be fetched from the panel with the right to read installations.")}
              foot={
                <Actions>
                  <Download path={created.config_url} label={t("Download the configuration")} />
                  <button type="button" onClick={() => copy("config-file", profile.data!.config.content)}>
                    {copied === "config-file" ? t("Copied") : t("Copy configuration")}
                  </button>
                  <button type="button" onClick={() => copy("ca-file", profile.data!.ca.pem)}>
                    {copied === "ca-file" ? t("Copied") : t("Copy CA")}
                  </button>
                  <button type="button" onClick={() => copy("fingerprint", profile.data!.ca.fingerprint_sha256)}>
                    {copied === "fingerprint" ? t("Copied") : t("Copy fingerprint")}
                  </button>
                </Actions>
              }
            >
              <Fields>
                <Field label={profile.data.config.path} wide hint={created.config_url}>
                  <textarea
                    readOnly
                    value={profile.data.config.content}
                    rows={Math.min(14, profile.data.config.content.split("\n").length)}
                    aria-label={profile.data.config.path}
                    data-testid="config-file"
                  />
                </Field>
                <Field
                  label={profile.data.ca.path}
                  wide
                  hint={t("{subject} · valid until {when}", {
                    subject: profile.data.ca.subject,
                    when: absoluteTime(profile.data.ca.not_after),
                  })}
                >
                  <textarea
                    readOnly
                    value={profile.data.ca.pem}
                    rows={Math.min(14, profile.data.ca.pem.split("\n").length)}
                    aria-label={profile.data.ca.path}
                    data-testid="ca-file"
                  />
                </Field>
                <Field
                  label={t("CA fingerprint")}
                  wide
                  hint={t("SHA-256 fingerprint of the signing CA; compare it with what openssl prints on the host.")}
                >
                  <input readOnly value={profile.data.ca.fingerprint_sha256} data-testid="fingerprint" />
                </Field>
              </Fields>
            </Card>
          )}

          <Card
            title={t("6. What the host has done so far")}
            note={ready
              ? t("Every stage is done; the host has a workspace of its own now.")
              : t("As the panel sees it — not as the agent declares it. A stopped step names its reason when the panel knows one.")}
            foot={
              <Actions>
                {state?.enrolled_host_id && state.kind === "agent" && (
                  <Link to={`/hosts/${state.enrolled_host_id}/overview`} data-testid="open-host">
                    {t("Open host")}
                  </Link>
                )}
                {!ready && (
                  <Note>
                    {live.connected
                      ? t("Watching the order live; a refusal or the host's arrival shows at once.")
                      : t("Refreshing every few seconds.")}
                  </Note>
                )}
              </Actions>
            }
            flush
          >
            {progress.error && <Problem>{String(progress.error)}</Problem>}
            <Table
              rows={steps}
              keyOf={(step) => step.key}
              rowTestId={(step) => `step-${step.key}`}
              testId="steps"
              empty={t("The order is placed; nothing has reached the panel from the host yet.")}
              columns={[
                {
                  key: "state",
                  head: t("State"),
                  cell: (step) => <Pill tone={stepTone(step)}>{stepWord(step.state, t)}</Pill>,
                },
                { key: "what", head: t("Stage"), cell: (step) => stepName(step.key, t) },
                {
                  key: "why",
                  head: t("Why it stopped"),
                  cell: (step) => step.error_code
                    ? <span title={step.error_code}>{errorMeaning(step.error_code, t) ?? step.detail ?? step.error_code}</span>
                    : null,
                },
              ]}
            />
          </Card>
        </>
      )}

      {/* The history of orders: what waits for a host, what came in and what
          was closed, within the operator's own scope. An open order is
          revoked, or revoked and replaced in one step; a closed one is copied
          - the same placement, route, owner, tags and pool of uses, with a
          token of its own shown once. No token of an earlier order comes
          back here. */}
      <Card
        title={t("Enrollment history")}
        tools={
          <select
            value={historyStatus}
            onChange={(event) => setHistoryStatus(event.target.value as EnrollmentOrder["status"] | "")}
            aria-label={t("Status")}
            data-testid="history-status"
          >
            <option value="pending">{t("pending")}</option>
            <option value="enrolled">{t("enrolled")}</option>
            <option value="expired">{t("expired")}</option>
            <option value="revoked">{t("revoked")}</option>
            <option value="failed">{t("failed")}</option>
            <option value="">{t("any status")}</option>
          </select>
        }
        flush
      >
        {list.error ? <Problem>{String(list.error)}</Problem> : list.isPending ? <Bones rows={4} /> : (
          <Table
            rows={orders}
            keyOf={(entry) => entry.id}
            rowTestId={(entry) => `order-${entry.id}`}
            testId="history"
            empty={historyStatus === "pending"
              ? t("No installation is waiting for a host right now.")
              : t("No order with this status.")}
            columns={[
              {
                key: "what",
                head: t("What for"),
                cell: (entry) => (
                  <>
                    {entry.description || "—"}
                    <Note>
                      {entry.relay_id
                        ? t("{kind} · {purpose} · via relay", { kind: entry.kind, purpose: entry.purpose })
                        : t("{kind} · {purpose}", { kind: entry.kind, purpose: entry.purpose })}
                    </Note>
                  </>
                ),
              },
              {
                key: "scope",
                head: t("Scope"),
                minor: true,
                tight: true,
                cell: (entry) => `${entry.site} / ${entry.environment}`,
              },
              {
                key: "status",
                head: t("Status"),
                cell: (entry) => <Pill tone={statusTone(entry.status)}>{statusWord(entry.status, t)}</Pill>,
              },
              {
                key: "uses",
                head: t("Uses"),
                num: true,
                cell: (entry) => `${entry.uses} / ${entry.max_uses}`,
              },
              {
                key: "expires",
                head: t("Expires"),
                minor: true,
                cell: (entry) => (
                  <span title={absoluteTime(entry.expires_at)}>{relativeTime(entry.expires_at)}</span>
                ),
              },
              {
                key: "by",
                head: t("Requested by"),
                minor: true,
                tight: true,
                cell: (entry) => entry.created_by,
              },
              {
                key: "do",
                head: "",
                actions: true,
                cell: (entry) => (
                  <Actions>
                    {entry.status === "pending" && (
                      <button
                        type="button"
                        onClick={() => revoke.mutate(entry.id)}
                        disabled={revoke.isPending}
                        data-testid={`revoke-${entry.id}`}
                      >
                        {t("Revoke")}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => replace.mutate(entry)}
                      disabled={replace.isPending || entry.purpose === "replace_identity"}
                      title={entry.purpose === "replace_identity"
                        ? t("An identity recovery order is placed on the host itself.")
                        : entry.status === "pending"
                          ? t("Revokes this order and places one like it; the new token is shown once.")
                          : t("Places an order like this one: the same placement, route, owner, tags and uses, with a new token shown once.")}
                      data-testid={`replace-${entry.id}`}
                    >
                      {entry.status === "pending" ? t("Revoke and replace") : t("Create similar")}
                    </button>
                  </Actions>
                ),
              },
            ]}
          />
        )}
      </Card>
    </Screen>
  );
}

/**
 * A refusal of the order the operator can do something about: a missing
 * reason is a field to fill in, a stale authentication is a sign-in that
 * comes back to the same place.
 */
function Refusal({ error, close }: { error: ApiError; close: () => void }) {
  const t = useT();
  if (error.code === "reauthentication_required") {
    return (
      <Banner
        tone="warn"
        actions={
          <>
            <button
              type="button"
              onClick={() => {
                // The address carries where to come back to and nothing else:
                // no token, no reason, nothing a proxy log should not hold.
                const target = encodeURIComponent(window.location.pathname);
                window.location.href = `/auth/login?step_up=1&redirect=${target}`;
              }}
              data-testid="sign-in-again"
            >
              {t("Sign in again")}
            </button>
            <button type="button" onClick={close}>{t("Close")}</button>
          </>
        }
      >
        {t("Re-authentication required.")} {error.message}
      </Banner>
    );
  }
  return (
    <Banner
      tone="error"
      actions={<button type="button" onClick={close} data-testid="close-refusal">{t("Close")}</button>}
    >
      {error.code === "reason_required"
        ? t("The order needs a reason: this placement, a batch token or a relay is a change the audit trail keeps the reason of.")
        : error.message}
    </Banner>
  );
}
