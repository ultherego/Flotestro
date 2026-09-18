import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Whoami } from "../lib/types";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * Notification channels.
 *
 * A channel is where the fleet reports to when nobody is looking at the
 * panel: a webhook of the installation's own, a mailbox, a chat room. It
 * names the subjects it carries and, for a fleet of many sites, the part
 * of the fleet it speaks for. A platform administrator writes one with a
 * reason; the test button says at once whether the address answers, and
 * the log below keeps every attempt with its typed reason, so a receiver
 * that is down is a row to read rather than a silence to wonder about.
 */

export type ChannelKind = "webhook" | "email" | "slack_webhook";

/**
 * A channel as the API serves it. The credential is never in it: the
 * address of an incoming webhook, the key a webhook is signed with and a
 * mail password live in the secret store, and the channel carries only
 * that one is configured and when it was last replaced.
 */
export type Channel = {
  id: string;
  name: string;
  kind: ChannelKind;
  config: Record<string, unknown>;
  /** The address in summary - the host of a webhook, the relay of a mailbox - with nothing secret in it. */
  public_config?: Record<string, unknown>;
  secret_configured?: boolean;
  secret_last_rotated_at?: string | null;
  revision?: number;
  events: string[];
  filter: { severity_min?: string; site?: string; environment?: string };
  enabled: boolean;
  created_by: string;
  reason: string;
  created_at: string;
  updated_at: string;
  last_delivery?: DeliverySummary | null;
};

/** The states of a row of the queue, as the schema names them. */
export type DeliveryState =
  | "pending" | "leased" | "delivered" | "retry_wait" | "dead_letter" | "suppressed";

/** What a channel says about its newest row. */
export type DeliverySummary = {
  id: string;
  state: DeliveryState;
  at: string;
  error_code?: string;
  /** The previous release's words, still served beside the state. */
  status?: "sent" | "failed";
  sent_at?: string;
  error?: string;
};

/**
 * One row of the queue: one event for one channel, with the attempts
 * counted on it and the outcome so far. A row is durable - a receiver
 * that is down delays it rather than losing it - so the table shows the
 * state, the attempt, when the next one is due and what went wrong last.
 */
export type Delivery = {
  id: string;
  channel_id: string;
  channel_name?: string;
  event_id: number;
  event_type: string;
  title?: string;
  state: DeliveryState;
  attempt: number;
  next_attempt_at: string;
  last_error_code: string;
  last_error: string;
  policy_id?: string;
  suppression_reason?: string;
  delivered_at?: string | null;
  created_at: string;
  updated_at: string;
  /** The previous release's words, derived from the state. */
  status: "sent" | "failed" | string;
  error_code: string;
  error: string;
  sent_at: string;
};

export type Subject = { name: string; description: string };

type ChannelList = Collection<Channel> & {
  kinds: ChannelKind[]; subjects: Subject[]; severities: string[]; states?: DeliveryState[];
};

/** The queue as the log asks for it: the page and the dead letters of the whole installation. */
type DeliveryList = Collection<Delivery> & { dead_letters?: number };

/** The form of a channel as it is edited, every kind's fields side by side. */
export type ChannelForm = {
  name: string;
  kind: ChannelKind;
  url: string;
  /** True while a stored incoming webhook has an address the form does not show. */
  urlSet: boolean;
  secret: string;
  /** True while a stored channel has a credential in the secret store. */
  secretSet: boolean;
  /** When that credential was last set or replaced; "" when there is none. */
  secretRotatedAt: string;
  /** False when the operator asked for the stored secret to be cleared. */
  keepSecret: boolean;
  host: string;
  port: string;
  starttls: boolean;
  from: string;
  /** The recipients, one per line or comma-separated. */
  to: string;
  username: string;
  passwordSecret: string;
  events: string[];
  severityMin: string;
  site: string;
  environment: string;
  enabled: boolean;
  reason: string;
};

export function emptyForm(kind: ChannelKind = "webhook"): ChannelForm {
  return {
    name: "", kind, url: "", urlSet: false, secret: "", secretSet: false, secretRotatedAt: "", keepSecret: true,
    host: "", port: "587", starttls: true, from: "", to: "", username: "", passwordSecret: "",
    events: ["alert.fired", "alert.resolved"], severityMin: "", site: "", environment: "",
    enabled: true, reason: "",
  };
}

/** The form of a stored channel. */
export function formOf(channel: Channel): ChannelForm {
  const config = channel.config ?? {};
  const text = (key: string) => (typeof config[key] === "string" ? (config[key] as string) : "");
  const to = Array.isArray(config.to) ? (config.to as unknown[]).map(String).join("\n") : "";
  return {
    name: channel.name,
    kind: channel.kind,
    url: text("url"),
    urlSet: config.url_set === true || (channel.kind === "slack_webhook" && channel.secret_configured === true),
    secret: "",
    // The channel says whether a credential is in the secret store; the
    // flag in the configuration is the same fact in the older shape.
    secretSet: channel.secret_configured === true || config.secret_set === true,
    secretRotatedAt: channel.secret_last_rotated_at ?? "",
    keepSecret: true,
    host: text("host"),
    port: config.port ? String(config.port) : "587",
    starttls: config.starttls !== false,
    from: text("from"),
    to,
    username: text("username"),
    passwordSecret: text("password_secret"),
    events: [...(channel.events ?? [])],
    severityMin: channel.filter?.severity_min ?? "",
    site: channel.filter?.site ?? "",
    environment: channel.filter?.environment ?? "",
    enabled: channel.enabled,
    reason: channel.reason ?? "",
  };
}

/** The recipients of the form as a list, empty lines and spaces dropped. */
export function recipients(text: string): string[] {
  return text.split(/[\n,;]+/).map((entry) => entry.trim()).filter(Boolean);
}

/**
 * The body the API takes, or what stops the form from being a channel.
 * The checks are the ones the server makes before writing, so a refusal
 * is read under the field rather than after the save.
 */
export function channelBody(form: ChannelForm): { body?: Record<string, unknown>; problem?: string } {
  if (form.name.trim() === "") return { problem: "name" };
  if (form.events.length === 0) return { problem: "events" };
  let config: Record<string, unknown> = {};
  switch (form.kind) {
    case "webhook": {
      if (!/^https?:\/\/\S+/.test(form.url.trim())) return { problem: "url" };
      config = { url: form.url.trim() };
      if (form.secret) config.secret = form.secret;
      else if (form.secretSet && form.keepSecret) config.secret_set = true;
      break;
    }
    case "slack_webhook": {
      // The address is the credential: a stored one is never shown back,
      // and an edit that leaves the field empty keeps it.
      if (form.url.trim() === "" && form.urlSet) config = { url_set: true };
      else if (!/^https?:\/\/\S+/.test(form.url.trim())) return { problem: "url" };
      else config = { url: form.url.trim() };
      break;
    }
    case "email": {
      const port = Number(form.port);
      if (form.host.trim() === "") return { problem: "host" };
      if (!Number.isInteger(port) || port < 1 || port > 65535) return { problem: "port" };
      if (!form.from.includes("@")) return { problem: "from" };
      const to = recipients(form.to);
      if (to.length === 0 || to.some((address) => !address.includes("@"))) return { problem: "to" };
      if (form.username.trim() && !form.passwordSecret.trim()) return { problem: "auth_secret" };
      if (form.username.trim() && !form.starttls) return { problem: "auth_tls" };
      config = {
        host: form.host.trim(), port, starttls: form.starttls, from: form.from.trim(), to,
        username: form.username.trim() || undefined, password_secret: form.passwordSecret.trim() || undefined,
      };
      break;
    }
  }
  if (form.reason.trim().length < 8) return { problem: "reason" };
  const filter: Record<string, string> = {};
  if (form.severityMin) filter.severity_min = form.severityMin;
  if (form.site.trim()) filter.site = form.site.trim();
  if (form.environment.trim()) filter.environment = form.environment.trim();
  return {
    body: {
      name: form.name.trim(), kind: form.kind, config, events: form.events, filter,
      enabled: form.enabled, reason: form.reason.trim(),
    },
  };
}

export function problemWords(t: (text: string, params?: Record<string, string | number>) => string, problem: string | undefined): string {
  switch (problem) {
    case "name": return t("the channel needs a name");
    case "events": return t("tick at least one event; a channel that carries nothing is not a channel");
    case "url": return t("the address has to be an http or https URL");
    case "host": return t("the mail relay needs a host");
    case "port": return t("the port has to lie between 1 and 65535");
    case "from": return t("the sender has to be a mail address");
    case "to": return t("every recipient has to be a mail address, and there has to be one");
    case "auth_secret": return t("a username needs the name of the secret that holds its password");
    case "auth_tls": return t("a password is sent only over STARTTLS");
    case "reason": return t("the reason needs at least 8 characters");
  }
  return "";
}

/** The address of a channel in one line, for the table. */
export function describeChannel(channel: Pick<Channel, "kind" | "config" | "public_config">): string {
  const config = channel.config ?? {};
  if (channel.kind === "email") {
    const to = Array.isArray(config.to) ? (config.to as unknown[]).map(String) : [];
    const relay = `${String(config.host ?? "")}:${String(config.port ?? "")}`;
    return `${to.join(", ")} via ${relay}${config.starttls === false ? "" : " (STARTTLS)"}`;
  }
  // An incoming webhook shows the host of its address and nothing of the
  // path: enough to tell a mistyped receiver from the right one, nothing
  // of the token the path carries.
  return String(config.url ?? channel.public_config?.display_host ?? "");
}

/** True for a stored incoming webhook whose address the API keeps to itself. */
export function addressWithheld(channel: Pick<Channel, "kind" | "config" | "secret_configured">): boolean {
  const config = channel.config ?? {};
  return channel.kind === "slack_webhook" && !config.url &&
    (config.url_set === true || channel.secret_configured === true);
}

/**
 * What the form says in place of a secret. The value itself is never
 * shown back - it left the panel for the secret store the moment it was
 * typed - so the operator is told the one thing that can be checked
 * without it: whether a credential is configured, and how old it is.
 */
export function secretWords(
  t: (text: string, params?: Record<string, string | number>) => string,
  form: Pick<ChannelForm, "secretSet" | "secretRotatedAt">,
  none: string,
): string {
  if (!form.secretSet) return none;
  if (!form.secretRotatedAt) {
    return t("A secret is configured; leave the field empty to keep it, or type a new one.");
  }
  return t("A secret is configured, last rotated {when}; leave the field empty to keep it, or type a new one.",
    { when: new Date(form.secretRotatedAt).toLocaleString() });
}

/** The name of a kind for the table and the form. */
export function kindLabel(t: (text: string) => string, kind: ChannelKind): string {
  switch (kind) {
    case "webhook": return t("Webhook (signed)");
    case "email": return t("E-mail (SMTP)");
    case "slack_webhook": return t("Slack-compatible webhook");
  }
  return kind;
}

/** The filter of a channel in words; nothing set is the whole fleet. */
export function describeFilter(t: (text: string) => string, filter: Channel["filter"] | undefined): string {
  const parts = [
    filter?.severity_min ? `severity ≥ ${filter.severity_min}` : "",
    filter?.site ? `site=${filter.site}` : "",
    filter?.environment ? `environment=${filter.environment}` : "",
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : t("whole fleet");
}

/** The window of the delivery log, in hours; "" is the whole month the log keeps. */
export type LogWindow = "" | "1" | "24" | "168";

/**
 * The query of the log for the screen's filter, the since moment computed
 * from the window. The filter's one word narrows by either vocabulary:
 * sent and failed are the previous release's and go out as status, every
 * state of the queue goes out as state. The server refuses a word neither
 * knows, so a typo is an answer rather than an empty table.
 */
export function deliveryParams(filter: { channel: string; status: string; window: LogWindow }, now: Date): URLSearchParams {
  const params = new URLSearchParams();
  if (filter.channel) params.set("channel_id", filter.channel);
  if (filter.status === "sent" || filter.status === "failed") params.set("status", filter.status);
  else if (filter.status) params.set("state", filter.status);
  if (filter.window) params.set("since", new Date(now.getTime() - Number(filter.window) * 3600 * 1000).toISOString());
  return params;
}

/** The outcome of a delivery in one line: sent, or the typed failure and its sentence. */
export function deliveryWords(
  t: (text: string, params?: Record<string, string | number>) => string,
  delivery: Partial<Pick<Delivery, "status" | "error_code" | "error" | "state" | "last_error_code" | "last_error">>,
): string {
  const code = delivery.last_error_code || delivery.error_code || "";
  const sentence = delivery.last_error || delivery.error || "";
  if (delivery.state === "delivered" || (!delivery.state && delivery.status === "sent")) return t("sent");
  if (delivery.state === "suppressed") return sentence || t("kept back");
  if (!code && !sentence) return t("failed");
  return sentence ? `${code}: ${sentence}` : code;
}

/** The state of a row of the queue in the words of the screen. */
export function stateWords(t: (text: string) => string, state: DeliveryState | string): string {
  switch (state) {
    case "pending": return t("queued");
    case "leased": return t("sending");
    case "delivered": return t("sent");
    case "retry_wait": return t("waiting to retry");
    case "dead_letter": return t("dead letter");
    case "suppressed": return t("kept back");
  }
  return state;
}

/** The colour a state reads in: delivered is well, a dead letter is not. */
export function stateTone(state: DeliveryState | string): string {
  switch (state) {
    case "delivered": return "ok";
    case "dead_letter": return "error";
    case "retry_wait": return "warn";
  }
  return "unknown";
}

/**
 * True for a row an operator can send again. Only a dead letter: a row
 * still waiting for its next attempt is the worker's, and pressing the
 * button on it would only reset the attempts of a receiver that is
 * coming back on its own.
 */
export function canRetry(delivery: Pick<Delivery, "state">): boolean {
  return delivery.state === "dead_letter";
}

/**
 * When the next attempt of a row is due, or "" for a row that has none: a
 * row that arrived, one that was kept back, a dead letter nobody put back
 * in the queue. Showing the column for those would read as a promise the
 * queue does not make.
 */
export function nextAttemptAt(delivery: Pick<Delivery, "state" | "next_attempt_at">): string {
  if (delivery.state !== "pending" && delivery.state !== "retry_wait") return "";
  return delivery.next_attempt_at ?? "";
}

function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function Notifications() {
  const t = useT();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const permissions = usePermissions();
  const canManage = permissions.has("notification.manage");
  const [editing, setEditing] = useState<ChannelForm | null>(null);
  const [editingID, setEditingID] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [testOutcome, setTestOutcome] = useState<{ id: string; delivery: Delivery } | null>(null);
  const [logFilter, setLogFilter] = useState<{ channel: string; status: string; window: LogWindow }>({ channel: "", status: "", window: "24" });

  const channels = useQuery({
    queryKey: ["notifications", "channels"],
    queryFn: () => api.get<ChannelList>("/api/v1/notifications/channels"),
    refetchInterval: 30000,
  });
  const logParams = deliveryParams(logFilter, new Date());
  const deliveries = useQuery({
    queryKey: ["notifications", "deliveries", logFilter.channel, logFilter.status, logFilter.window],
    queryFn: () => {
      const params = new URLSearchParams(logParams);
      params.set("limit", "100");
      return api.get<DeliveryList>(`/api/v1/notifications/deliveries?${params}`);
    },
    refetchInterval: 30000,
  });
  const deadLetters = deliveries.data?.dead_letters ?? 0;

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });
  const failed = (error: unknown) => {
    setErrorMessage(errorText(error));
    toast.error(errorText(error));
  };

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => editingID
      ? api.put<Channel>(`/api/v1/notifications/channels/${editingID}`, body)
      : api.post<Channel>("/api/v1/notifications/channels", body),
    onSuccess: (channel) => {
      setEditing(null); setEditingID(""); setErrorMessage("");
      toast.success(editingID ? t("Channel {name} is saved.", { name: channel.name }) : t("Channel {name} is created.", { name: channel.name }));
      refresh();
    },
    onError: failed,
  });
  // Disabling and enabling rewrite the record with the flag flipped: the
  // API has one write, and the reason of the toggle goes on the record.
  const toggle = useMutation({
    mutationFn: ({ channel, reason }: { channel: Channel; reason: string }) => {
      const form = formOf(channel);
      const check = channelBody({ ...form, enabled: !channel.enabled, reason });
      if (!check.body) throw new Error(problemWords(t, check.problem));
      return api.put<Channel>(`/api/v1/notifications/channels/${channel.id}`, check.body);
    },
    onSuccess: (channel) => {
      toast.success(channel.enabled ? t("Channel {name} is enabled.", { name: channel.name }) : t("Channel {name} is disabled.", { name: channel.name }));
      refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del<void>(`/api/v1/notifications/channels/${id}`, { reason }),
    onSuccess: () => { toast.success(t("The channel is deleted with its log.")); refresh(); },
    onError: failed,
  });
  // A dead letter is put back in the queue by hand: the message was never
  // received, the row still carries it, and the worker takes it again as
  // soon as the operator has mended what refused it.
  const retry = useMutation({
    mutationFn: (id: string) => api.post<Delivery>(`/api/v1/notifications/deliveries/${id}/retry`),
    onSuccess: () => {
      toast.success(t("The message is back in the queue; the next attempt goes out in a moment."));
      setErrorMessage("");
      refresh();
    },
    onError: failed,
  });
  const test = useMutation({
    mutationFn: (id: string) => api.post<Delivery>(`/api/v1/notifications/channels/${id}/test`),
    onSuccess: (delivery, id) => {
      setTestOutcome({ id, delivery });
      if (delivery.state === "delivered" || delivery.status === "sent") toast.success(t("The test message went out."));
      else toast.error(t("The test message did not arrive: {reason}", { reason: deliveryWords(t, delivery) }));
      refresh();
    },
    onError: failed,
  });

  const askToggle = async (channel: Channel) => {
    const { ok, reason } = await confirm({
      title: channel.enabled ? t("Disable the channel {name}?", { name: channel.name }) : t("Enable the channel {name}?", { name: channel.name }),
      body: <p>{channel.enabled
        ? t("Nothing is sent through it until it is enabled again; the events of that time are not sent later.")
        : t("It carries every event from now on; the events of the time it was disabled are not sent.")}</p>,
      confirmLabel: channel.enabled ? t("Disable") : t("Enable"),
      reason: { required: true },
    });
    if (ok && reason) toggle.mutate({ channel, reason });
  };
  const askRemove = async (channel: Channel) => {
    const { ok, reason } = await confirm({
      title: t("Delete the channel {name}?", { name: channel.name }),
      body: <p>{t("Its delivery log goes with it; the audit trail keeps who wrote and removed it.")}</p>,
      confirmLabel: t("Delete"),
      danger: true,
      reason: { required: true },
    });
    if (ok && reason) remove.mutate({ id: channel.id, reason });
  };

  if (channels.error) return <ErrorBox error={channels.error} />;
  const items = channels.data?.items ?? [];
  const subjects = channels.data?.subjects ?? [];
  const severities = channels.data?.severities ?? ["info", "warning", "critical"];
  // The states the queue really has; the server sends them so the filter
  // is never a list written twice.
  const states = channels.data?.states ?? [];
  const check = editing ? channelBody(editing) : undefined;

  return (
    <>
      <PageHeader
        icon="notifications"
        title={t("Notifications")}
        description={t("Where the fleet reports to when nobody is looking at the panel: a webhook, a mailbox, a chat room. Every attempt is in the log below with its reason.")}
        breadcrumb={[{ label: t("Monitoring"), to: "/monitoring" }]}
        actions={canManage && (
          <button className="primary" onClick={() => { setEditing(emptyForm()); setEditingID(""); setErrorMessage(""); }} disabled={Boolean(editing)}>
            {t("New channel")}
          </button>
        )}
      />

      {errorMessage && <p className="page-error">{errorMessage}</p>}

      {editing && (
        <Card
          title={editingID ? t("Edit the channel") : t("New channel")}
          description={t("No credential lies in the channel: the address of an incoming webhook, the key a webhook is signed with and a mail password go to the secret store the moment they are typed and are never shown back. The form says only whether one is configured and when it was last rotated; an empty field keeps the stored one.")}
        >
          <ChannelFields form={editing} subjects={subjects} severities={severities} onChange={setEditing} />
          <Actions>
            <button onClick={() => check?.body && save.mutate(check.body)} disabled={save.isPending || !check?.body}>
              {save.isPending ? t("Saving…") : editingID ? t("Save the channel") : t("Create the channel")}
            </button>
            <button className="secondary" onClick={() => { setEditing(null); setEditingID(""); }}>{t("Cancel")}</button>
            {check?.problem && <span className="source">{problemWords(t, check.problem)}</span>}
          </Actions>
        </Card>
      )}

      <div className="widgets">
        <Card className="span-12" title={t("Channels")} flush
          description={t("Each channel carries the events it names for the part of the fleet its filter keeps; a disabled one is listed because it would carry again the moment somebody enables it.")}>
          {!channels.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : items.length === 0 ? (
            <EmptyState action={canManage && !editing && (
              <button className="secondary" onClick={() => { setEditing(emptyForm()); setEditingID(""); }}>{t("New channel")}</button>
            )}>
              {t("No channels: the alerts fire and the campaigns end, but nobody is told outside the panel.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Address")}</th><th>{t("Events")}</th>
                  <th>{t("Filter")}</th><th>{t("Last delivery")}</th>{canManage && <th>{t("Actions")}</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((channel) => (
                  <ChannelRow
                    key={channel.id}
                    channel={channel}
                    canManage={canManage}
                    busy={test.isPending || toggle.isPending || remove.isPending}
                    outcome={testOutcome?.id === channel.id ? testOutcome.delivery : undefined}
                    onTest={() => test.mutate(channel.id)}
                    onEdit={() => { setEditing(formOf(channel)); setEditingID(channel.id); setErrorMessage(""); }}
                    onToggle={() => askToggle(channel)}
                    onRemove={() => askRemove(channel)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-12"
          title={
            <>
              {t("Delivery queue")}
              {deadLetters > 0 && (
                <>
                  {" "}
                  <span className="badge error" title={t("Messages nobody received: the attempts ran out or the receiver refused the credentials. They wait here until an operator sends them again.")}>
                    {t("{n} dead letters", { n: deadLetters })}
                  </span>
                </>
              )}
            </>
          }
          description={t("One row per event and channel, newest first. A receiver that is down delays a message rather than losing it: the row waits, the attempts are counted on it, and a message nobody received ends as a dead letter an operator sends again.")}
          actions={
            <>
              <select value={logFilter.channel} onChange={(e) => setLogFilter({ ...logFilter, channel: e.target.value })}>
                <option value="">{t("every channel")}</option>
                {items.map((channel) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
              </select>
              <select value={logFilter.status} onChange={(e) => setLogFilter({ ...logFilter, status: e.target.value })}>
                <option value="">{t("every state")}</option>
                <option value="sent">{t("sent")}</option>
                <option value="failed">{t("failed")}</option>
                {states.map((state) => <option key={state} value={state}>{stateWords(t, state)}</option>)}
              </select>
              <select value={logFilter.window} onChange={(e) => setLogFilter({ ...logFilter, window: e.target.value as LogWindow })}>
                <option value="1">{t("last hour")}</option>
                <option value="24">{t("last 24 hours")}</option>
                <option value="168">{t("last 7 days")}</option>
                <option value="">{t("the whole month")}</option>
              </select>
              <ExportButton path="/api/v1/notifications/deliveries" params={logParams} />
            </>
          }
          flush
        >
          {deliveries.error ? (
            <ErrorBox error={deliveries.error} />
          ) : !deliveries.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : deliveries.data.items.length === 0 ? (
            <Empty>{items.length === 0 && channels.data ? t("Nothing has been sent yet: there is no channel to send to.") : t("No delivery matches the filter.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("When")}</th><th>{t("Channel")}</th><th>{t("Event")}</th>
                  <th>{t("State")}</th><th className="num">{t("Attempt")}</th><th>{t("Next attempt")}</th>
                  <th>{t("Last error")}</th>{canManage && <th>{t("Actions")}</th>}
                </tr>
              </thead>
              <tbody>
                {deliveries.data.items.map((delivery) => {
                  const next = nextAttemptAt(delivery);
                  return (
                    <tr key={delivery.id}>
                      <td><Time value={delivery.updated_at || delivery.sent_at} /></td>
                      <td>{delivery.channel_name || delivery.channel_id.slice(0, 8)}</td>
                      <td>
                        <div className="fp-host-cell">
                          <span className="hm-mono">{delivery.event_type}</span>
                          {delivery.title && <span className="source">{delivery.title}</span>}
                          {!delivery.title && delivery.event_id > 0 && <span className="source">#{delivery.event_id}</span>}
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${stateTone(delivery.state)}`}>{stateWords(t, delivery.state)}</span>
                      </td>
                      <td className="num">{delivery.attempt}</td>
                      <td>{next ? <Time value={next} /> : <span className="source">—</span>}</td>
                      <td>
                        {delivery.last_error_code
                          ? <div className="fp-host-cell">
                              <span className="hm-mono">{delivery.last_error_code}</span>
                              {delivery.last_error && <span className="source">{delivery.last_error}</span>}
                            </div>
                          : <span className="source">{deliveryWords(t, delivery)}</span>}
                      </td>
                      {canManage && (
                        <td>
                          {canRetry(delivery) && (
                            <button className="secondary" disabled={retry.isPending}
                              onClick={() => retry.mutate(delivery.id)}>
                              {t("Retry")}
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

function ChannelRow({ channel, canManage, busy, outcome, onTest, onEdit, onToggle, onRemove }: {
  channel: Channel; canManage: boolean; busy: boolean; outcome?: Delivery;
  onTest: () => void; onEdit: () => void; onToggle: () => void; onRemove: () => void;
}) {
  const t = useT();
  const last = channel.last_delivery;
  return (
    <>
      <tr>
        <td>
          <div className="fp-host-cell">
            <span>{channel.name}{!channel.enabled && <> <span className="badge unknown">{t("disabled")}</span></>}</span>
            <span className="source">{channel.created_by}</span>
          </div>
        </td>
        <td>{kindLabel(t, channel.kind)}</td>
        <td className="hm-mono">{addressWithheld(channel) ? t("URL is set") : describeChannel(channel)}</td>
        <td className="source">{channel.events.length ? channel.events.join(", ") : t("nothing")}</td>
        <td className="source">{describeFilter(t, channel.filter)}</td>
        <td>
          {last ? (
            <div className="fp-host-cell">
              <span>
                <span className={`badge ${stateTone(last.state)}`}>{stateWords(t, last.state)}</span>
                {" "}<Time value={last.at || last.sent_at || ""} />
              </span>
              {last.error_code && <span className="source">{last.error_code}</span>}
            </div>
          ) : <span className="source">{t("nothing sent yet")}</span>}
        </td>
        {canManage && (
          <td>
            <Actions>
              <button className="secondary" onClick={onTest} disabled={busy}>{t("Send a test")}</button>
              <button className="secondary" onClick={onEdit}>{t("Edit")}</button>
              <button className="secondary" onClick={onToggle} disabled={busy}>{channel.enabled ? t("Disable") : t("Enable")}</button>
              <button className="secondary" onClick={onRemove} disabled={busy}>{t("Delete")}</button>
            </Actions>
          </td>
        )}
      </tr>
      {outcome && (
        <tr>
          <td colSpan={canManage ? 7 : 6}>
            {outcome.state === "delivered" || outcome.status === "sent"
              ? <span className="badge ok">{t("The test message went out at {when}.", { when: new Date(outcome.sent_at).toLocaleString() })}</span>
              : <><span className="badge error">{t("The test failed")}</span> <span className="source">{deliveryWords(t, outcome)}</span></>}
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The fields of a channel: the kind chooses which address fields show,
 * the events are ticked from the catalogue the server sent, and the
 * filter narrows by severity, site and environment.
 */
function ChannelFields({ form, subjects, severities, onChange }: {
  form: ChannelForm; subjects: Subject[]; severities: string[]; onChange: (form: ChannelForm) => void;
}) {
  const t = useT();
  const set = (patch: Partial<ChannelForm>) => onChange({ ...form, ...patch });
  const toggleEvent = (name: string) => set({
    events: form.events.includes(name) ? form.events.filter((event) => event !== name) : [...form.events, name],
  });
  return (
    <FieldGrid>
      <Field label={t("Name")}>
        <input value={form.name} onChange={(e) => set({ name: e.target.value })} />
      </Field>
      <Field label={t("Kind")}>
        <select value={form.kind} onChange={(e) => set({ kind: e.target.value as ChannelKind })}>
          <option value="webhook">{kindLabel(t, "webhook")}</option>
          <option value="slack_webhook">{kindLabel(t, "slack_webhook")}</option>
          <option value="email">{kindLabel(t, "email")}</option>
        </select>
      </Field>

      {form.kind !== "email" && (
        <Field label={t("Address")} wide
          hint={form.kind === "webhook"
            ? t("The deliveries are JSON, signed with HMAC-SHA256 over the body and the timestamp like the webhook of the environment file.")
            : form.urlSet
              ? secretWords(t, form, t("URL is set; leave the field empty to keep it, or type a new one. The address is the credential of the channel and is never shown back."))
              : t("An incoming webhook of Slack, or of a service that reads its shape: the body is {text, blocks}.")}>
          <input value={form.url} onChange={(e) => set({ url: e.target.value })} className="mono" placeholder={form.urlSet ? t("URL is set") : "https://"} />
        </Field>
      )}
      {form.kind === "webhook" && (
        <Field label={t("Signing secret")} wide
          hint={secretWords(t, form, t("Empty means the deliveries are not signed in a way the receiver can verify."))}>
          <input type="password" autoComplete="new-password" value={form.secret} onChange={(e) => set({ secret: e.target.value })} className="mono" />
        </Field>
      )}
      {form.kind === "webhook" && form.secretSet && (
        <div className="field">
          <label className="toggle">
            <input type="checkbox" checked={!form.keepSecret} onChange={(e) => set({ keepSecret: !e.target.checked })} />{" "}
            {t("clear the stored secret")}
          </label>
        </div>
      )}

      {form.kind === "email" && (
        <>
          <Field label={t("Mail relay host")}>
            <input value={form.host} onChange={(e) => set({ host: e.target.value })} className="mono" />
          </Field>
          <Field label={t("Port")}>
            <input type="number" min={1} max={65535} value={form.port} onChange={(e) => set({ port: e.target.value })} />
          </Field>
          <Field label={t("From")}>
            <input value={form.from} onChange={(e) => set({ from: e.target.value })} className="mono" placeholder="flotestro@example.com" />
          </Field>
          <Field label={t("Recipients")} hint={t("One per line or comma-separated; at most twenty.")}>
            <textarea rows={3} value={form.to} onChange={(e) => set({ to: e.target.value })} className="mono" />
          </Field>
          <Field label={t("Username")} hint={t("Empty means the relay takes mail without a login.")}>
            <input value={form.username} onChange={(e) => set({ username: e.target.value })} className="mono" autoComplete="off" />
          </Field>
          <Field label={t("Password secret")} hint={t("The name of a secret of the secret store; the password itself is never written here.")}>
            <input value={form.passwordSecret} onChange={(e) => set({ passwordSecret: e.target.value })} className="mono" />
          </Field>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={form.starttls} onChange={(e) => set({ starttls: e.target.checked })} />{" "}
              {t("STARTTLS (required for a login)")}
            </label>
          </div>
        </>
      )}

      <div className="field wide">
        <span className="field-label">{t("Events")}</span>
        {subjects.map((subject) => (
          <label key={subject.name} className="toggle">
            <input type="checkbox" checked={form.events.includes(subject.name)} onChange={() => toggleEvent(subject.name)} />{" "}
            <span className="hm-mono">{subject.name}</span> <span className="source">{subject.description}</span>
          </label>
        ))}
      </div>

      <Field label={t("Least severity")} hint={t("Alerts below it are not carried; the other events have no severity and pass.")}>
        <select value={form.severityMin} onChange={(e) => set({ severityMin: e.target.value })}>
          <option value="">{t("every severity")}</option>
          {severities.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
        </select>
      </Field>
      <Field label={t("Site")} hint={t("Empty means every site; an event that names no host passes.")}>
        <input value={form.site} onChange={(e) => set({ site: e.target.value })} />
      </Field>
      <Field label={t("Environment")}>
        <input value={form.environment} onChange={(e) => set({ environment: e.target.value })} />
      </Field>
      <Field label={t("Reason or change reference")} wide hint={t("Kept in the audit trail with the channel.")}>
        <input value={form.reason} onChange={(e) => set({ reason: e.target.value })} />
      </Field>
      <div className="field">
        <label className="toggle">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />{" "}
          {t("enabled")}
        </label>
      </div>
    </FieldGrid>
  );
}
