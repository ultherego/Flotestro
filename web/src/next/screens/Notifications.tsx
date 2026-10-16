import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Whoami } from "../../lib/types";
import { useToast } from "../../components/Toast";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Banner, Bones, Button, Card, Check, type Column, Download, Empty, Field, Fields,
  Kpi, Modal, Note, Pill, Problem, Row, Stack, Table, Toolbar, TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * Where the fleet reports to when nobody is looking at the panel.
 *
 * Two things live here and they answer two different questions. A channel
 * is a standing arrangement - this webhook, that mailbox, these events -
 * and the queue underneath is what actually happened to each message. A
 * receiver that is down delays a message rather than losing it: the row
 * waits, the attempts are counted on it, and a message nobody received
 * ends as a dead letter an operator puts back by hand.
 *
 * No credential is ever on this screen. The address of an incoming
 * webhook, the key a webhook is signed with and a mail password go to the
 * secret store the moment they are typed and are never served back; the
 * form says only whether one is configured and when it was last rotated.
 */

export type ChannelKind = "webhook" | "email" | "slack_webhook";

/** A channel as the API serves it. */
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
 * One row of the queue: one event for one channel, with the attempts counted
 * on it and the outcome so far.
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

/** The queue as the log asks for it: the page, and the dead letters of the whole installation. */
export type DeliveryList = Collection<Delivery> & { dead_letters?: number };

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
    name: "", kind, url: "", urlSet: false, secret: "", secretSet: false, secretRotatedAt: "",
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

/** The body the API takes, or what stops the form from being a channel. */
export function channelBody(form: ChannelForm): { body?: Record<string, unknown>; problem?: string } {
  if (form.name.trim() === "") return { problem: "name" };
  if (form.events.length === 0) return { problem: "events" };
  let config: Record<string, unknown> = {};
  switch (form.kind) {
    case "webhook": {
      if (!/^https?:\/\/\S+/.test(form.url.trim())) return { problem: "url" };
      config = { url: form.url.trim() };
      // A webhook is signed or it is not a channel: a body signed with an
      // empty key is one anybody can forge.
      if (form.secret) config.secret = form.secret;
      else if (form.secretSet) config.secret_set = true;
      else return { problem: "secret" };
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

export function problemWords(t: Translate, problem: string | undefined): string {
  switch (problem) {
    case "name": return t("the channel needs a name");
    case "events": return t("tick at least one event; a channel that carries nothing is not a channel");
    case "url": return t("the address has to be an http or https URL");
    case "host": return t("the mail relay needs a host");
    case "port": return t("the port has to lie between 1 and 65535");
    case "from": return t("the sender has to be a mail address");
    case "to": return t("every recipient has to be a mail address, and there has to be one");
    case "secret": return t("a webhook needs a signing secret; a delivery signed with an empty key is one anybody can forge");
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
  // path: enough to tell a mistyped receiver from the right one, nothing of
  // the token the path carries.
  return String(config.url ?? channel.public_config?.display_host ?? "");
}

/** True for a stored incoming webhook whose address the API keeps to itself. */
export function addressWithheld(channel: Pick<Channel, "kind" | "config" | "secret_configured">): boolean {
  const config = channel.config ?? {};
  return channel.kind === "slack_webhook" && !config.url &&
    (config.url_set === true || channel.secret_configured === true);
}

/** What the form says in place of a secret. */
export function secretWords(
  t: Translate,
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
export function kindLabel(t: Translate, kind: ChannelKind): string {
  switch (kind) {
    case "webhook": return t("Webhook (signed)");
    case "email": return t("E-mail (SMTP)");
    case "slack_webhook": return t("Slack-compatible webhook");
  }
  return kind;
}

/** The filter of a channel in words; nothing set is the whole fleet. */
export function describeFilter(t: Translate, filter: Channel["filter"] | undefined): string {
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
 * from the window.
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
  t: Translate,
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
export function stateWords(t: Translate, state: DeliveryState | string): string {
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
export function stateTone(state: DeliveryState | string): Tone {
  switch (state) {
    case "delivered": return "ok";
    case "dead_letter": return "error";
    case "retry_wait": return "warn";
  }
  return "unknown";
}

/** True for a row an operator can send again. */
export function canRetry(delivery: Pick<Delivery, "state">): boolean {
  return delivery.state === "dead_letter";
}

/**
 * When the next attempt of a row is due, or "" for a row that has none: a
 * row that arrived, one that was kept back, a dead letter nobody put back in
 * the queue.
 */
export function nextAttemptAt(delivery: Pick<Delivery, "state" | "next_attempt_at">): string {
  if (delivery.state !== "pending" && delivery.state !== "retry_wait") return "";
  return delivery.next_attempt_at ?? "";
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** How often the channels and the queue are read again. */
const POLL = 30000;

/** How many rows of the queue one read brings back. */
const QUEUE_PAGE = 100;

/** What a decision waiting on a sentence is about. */
type Asking = { what: "enable" | "disable" | "delete"; channel: Channel };

export function Notifications() {
  const t = useT();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<ChannelForm | null>(null);
  const [editingID, setEditingID] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [asking, setAsking] = useState<Asking | null>(null);
  const [testOutcome, setTestOutcome] = useState<{ id: string; delivery: Delivery } | null>(null);
  const [logFilter, setLogFilter] = useState<{ channel: string; status: string; window: LogWindow }>(
    { channel: "", status: "", window: "24" },
  );

  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canManage = (me.data?.permissions ?? []).includes("notification.manage");

  const channels = useQuery({
    queryKey: ["notifications", "channels"],
    queryFn: () => api.get<ChannelList>("/api/v1/notifications/channels"),
    refetchInterval: POLL,
    retry: false,
  });
  const logParams = deliveryParams(logFilter, new Date());
  const deliveries = useQuery({
    queryKey: ["notifications", "deliveries", logFilter.channel, logFilter.status, logFilter.window],
    queryFn: () => {
      const params = new URLSearchParams(logParams);
      params.set("limit", String(QUEUE_PAGE));
      return api.get<DeliveryList>(`/api/v1/notifications/deliveries?${params}`);
    },
    refetchInterval: POLL,
    retry: false,
  });

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
      toast.success(editingID
        ? t("Channel {name} is saved.", { name: channel.name })
        : t("Channel {name} is created.", { name: channel.name }));
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
      setAsking(null);
      toast.success(channel.enabled
        ? t("Channel {name} is enabled.", { name: channel.name })
        : t("Channel {name} is disabled.", { name: channel.name }));
      refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del<void>(`/api/v1/notifications/channels/${id}`, { reason }),
    onSuccess: () => {
      setAsking(null);
      toast.success(t("The channel is deleted with its log."));
      refresh();
    },
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

  if (channels.error instanceof ApiError && channels.error.forbidden) {
    return (
      <Empty>
        {t("You may not read the notification channels of this installation.")}
      </Empty>
    );
  }
  if (channels.error) return <Problem>{errorText(channels.error)}</Problem>;

  const items = channels.data?.items ?? [];
  const subjects = channels.data?.subjects ?? [];
  const severities = channels.data?.severities ?? ["info", "warning", "critical"];
  // The states the queue really has; the server sends them so the filter
  // is never a list written twice.
  const states = channels.data?.states ?? [];
  const loaded = channels.data !== undefined;
  const check = editing ? channelBody(editing) : undefined;

  const rows = deliveries.data?.items ?? [];
  const queueRead = deliveries.data !== undefined;
  // The dead letters are the installation's own count and not a tally of
  // the page: a filter that hides them does not make them fewer. Until the
  // queue has answered nobody has counted anything, which is not nought.
  const deadLetters = queueRead ? deliveries.data?.dead_letters : undefined;
  const carrying = loaded ? items.filter((one) => one.enabled).length : undefined;

  const count = (state: DeliveryState) =>
    (queueRead ? rows.filter((one) => one.state === state).length : undefined);
  const queueStates: Segment[] = [
    { label: t("sent"), value: count("delivered"), tone: "ok" },
    { label: t("queued"), value: count("pending"), tone: "info" },
    { label: t("waiting to retry"), value: count("retry_wait"), tone: "warn" },
    { label: t("dead letter"), value: count("dead_letter"), tone: "error" },
    { label: t("kept back"), value: count("suppressed"), tone: "neutral" },
  ];

  const newChannel = () => { setEditing(emptyForm()); setEditingID(""); setErrorMessage(""); };
  const tested = testOutcome ? items.find((one) => one.id === testOutcome.id) : undefined;

  const channelColumns: Column<Channel>[] = [
    { key: "name", head: t("Name"), cell: (one) => (
      <TwoLine sub={one.created_by}>
        {one.name}
        {!one.enabled && <> <Pill tone="unknown">{t("disabled")}</Pill></>}
      </TwoLine>
    ) },
    { key: "kind", head: t("Kind"), cell: (one) => kindLabel(t, one.kind) },
    // The address is read as one word - a URL broken over two lines reads
    // as two receivers - and an incoming webhook's is never shown at all.
    { key: "address", head: t("Address"), tight: true, cell: (one) => (
      addressWithheld(one)
        ? <span>{t("URL is set")}</span>
        : <code title={describeChannel(one)}>{describeChannel(one)}</code>
    ) },
    { key: "events", head: t("Events"), minor: true, cell: (one) => (
      one.events.length > 0 ? one.events.join(", ") : t("nothing")
    ) },
    { key: "filter", head: t("Filter"), minor: true, cell: (one) => describeFilter(t, one.filter) },
    { key: "last", head: t("Last delivery"), cell: (one) => <LastDelivery last={one.last_delivery} /> },
  ];
  if (canManage) {
    channelColumns.push({
      key: "do", actions: true, cell: (one) => (
        <Actions>
          <Button kind="quiet" onClick={() => test.mutate(one.id)} disabled={test.isPending}
                  testId={`test-${one.id}`}>{t("Send a test")}</Button>
          <Button kind="quiet" testId={`edit-${one.id}`}
                  onClick={() => { setEditing(formOf(one)); setEditingID(one.id); setErrorMessage(""); }}>
            {t("Edit")}
          </Button>
          <Button kind="quiet" disabled={toggle.isPending} testId={`toggle-${one.id}`}
                  onClick={() => setAsking({ what: one.enabled ? "disable" : "enable", channel: one })}>
            {one.enabled ? t("Disable") : t("Enable")}
          </Button>
          <Button kind="danger" disabled={remove.isPending} testId={`delete-${one.id}`}
                  onClick={() => setAsking({ what: "delete", channel: one })}>
            {t("Delete")}
          </Button>
        </Actions>
      ),
    });
  }

  const deliveryColumns: Column<Delivery>[] = [
    { key: "when", head: t("When"), cell: (one) => (
      <span title={absoluteTime(one.updated_at || one.sent_at)}>
        {relativeTime(one.updated_at || one.sent_at)}
      </span>
    ) },
    { key: "channel", head: t("Channel"), cell: (one) => one.channel_name || one.channel_id.slice(0, 8) },
    { key: "event", head: t("Event"), cell: (one) => (
      <TwoLine sub={one.title || (one.event_id > 0 ? `#${one.event_id}` : undefined)}>
        <code>{one.event_type}</code>
      </TwoLine>
    ) },
    { key: "state", head: t("State"), cell: (one) => (
      <Pill tone={stateTone(one.state)}>{stateWords(t, one.state)}</Pill>
    ) },
    { key: "attempt", head: t("Attempt"), num: true, cell: (one) => one.attempt },
    // A row that has arrived, one that was kept back and a dead letter
    // nobody put back have no next attempt: that is an em dash, not a date.
    { key: "next", head: t("Next attempt"), minor: true, cell: (one) => {
      const next = nextAttemptAt(one);
      return next
        ? <span title={absoluteTime(next)}>{relativeTime(next)}</span>
        : <span className="fl-faint">—</span>;
    } },
    { key: "error", head: t("Last error"), tight: true, cell: (one) => (
      one.last_error_code
        ? <TwoLine sub={one.last_error || undefined}><code>{one.last_error_code}</code></TwoLine>
        : <span className="fl-faint">{deliveryWords(t, one)}</span>
    ) },
  ];
  if (canManage) {
    deliveryColumns.push({
      key: "do", actions: true, cell: (one) => (
        canRetry(one)
          ? (
            <Button kind="quiet" disabled={retry.isPending} testId={`retry-${one.id}`}
                    onClick={() => retry.mutate(one.id)}>
              {t("Retry")}
            </Button>
          )
          : null
      ),
    });
  }

  return (
    <>
      {asking?.what === "delete" && (
        <ReasonModal
          title={t("Delete the channel {name}?", { name: asking.channel.name })}
          body={t("Its delivery log goes with it; the audit trail keeps who wrote and removed it.")}
          confirm={t("Delete")}
          danger
          busy={remove.isPending}
          onClose={() => setAsking(null)}
          onConfirm={(reason) => remove.mutate({ id: asking.channel.id, reason })}
        />
      )}
      {asking && asking.what !== "delete" && (
        <ReasonModal
          title={asking.what === "disable"
            ? t("Disable the channel {name}?", { name: asking.channel.name })
            : t("Enable the channel {name}?", { name: asking.channel.name })}
          body={asking.what === "disable"
            ? t("Nothing is sent through it until it is enabled again; the events of that time are not sent later.")
            : t("It carries every event from now on; the events of the time it was disabled are not sent.")}
          confirm={asking.what === "disable" ? t("Disable") : t("Enable")}
          busy={toggle.isPending}
          onClose={() => setAsking(null)}
          onConfirm={(reason) => toggle.mutate({ channel: asking.channel, reason })}
        />
      )}

      <Board
        screen={NOTIFICATIONS_SCREEN}
        catalogue={NOTIFICATIONS}
        /* What the server refused stays on the screen until it is read.
           A toast says it once and goes; a write that failed is a fact
           about the installation until somebody has dealt with it. */
        notices={errorMessage ? (
          <Banner
            tone="error"
            actions={<Button kind="quiet" onClick={() => setErrorMessage("")}>{t("Close")}</Button>}
          >
            {errorMessage}
          </Banner>
        ) : null}
        drawn={{
        channels_count: (
          <Kpi
            hero
            icon="notifications"
            label={t("Channels")}
            value={loaded ? items.length : null}
            note={t("Where the fleet reports when nobody is watching the panel.")}
          />
        ),
        carrying: (
          <Kpi
            icon="check"
            label={t("Carrying events")}
            value={carrying}
            tone={carrying === 0 ? "warn" : "ok"}
            note={t("A disabled channel is listed because it would carry again the moment somebody enables it.")}
          />
        ),
        dead: (
          <Kpi
            icon="notifications"
            label={t("Dead letters")}
            value={deadLetters}
            tone={deadLetters && deadLetters > 0 ? "error" : "ok"}
            note={t("Messages nobody received: the attempts ran out or the receiver refused the credentials. They wait here until an operator sends them again.")}
          />
        ),
        form: editing && (
          <Card
            title={editingID ? t("Edit the channel") : t("New channel")}
            note={t("No credential lies in the channel: the address of an incoming webhook, the key a webhook is signed with and a mail password go to the secret store the moment they are typed and are never shown back. The form says only whether one is configured and when it was last rotated; an empty field keeps the stored one.")}
          >
            <Stack>
              <ChannelFields form={editing} subjects={subjects} severities={severities} onChange={setEditing} />
              <Actions>
                <Button
                  onClick={() => check?.body && save.mutate(check.body)}
                  disabled={save.isPending || !check?.body}
                  testId="save-channel"
                >
                  {save.isPending ? t("Saving…") : editingID ? t("Save the channel") : t("Create the channel")}
                </Button>
                <Button kind="quiet" onClick={() => { setEditing(null); setEditingID(""); }}>{t("Cancel")}</Button>
                {/* Why the form will not go yet, in the reader's words
                    rather than as a button that simply does nothing. */}
                {check?.problem && <Note>{problemWords(t, check.problem)}</Note>}
              </Actions>
            </Stack>
          </Card>
        ),
        channels: (
          <Card
            title={t("Channels")}
            flush
            note={t("Each channel carries the events it names for the part of the fleet its filter keeps; a disabled one is listed because it would carry again the moment somebody enables it.")}
            tools={canManage && (
              <Button onClick={newChannel} disabled={Boolean(editing)} testId="new-channel">
                {t("New channel")}
              </Button>
            )}
            foot={tested && testOutcome && (
              testOutcome.delivery.state === "delivered" || testOutcome.delivery.status === "sent"
                ? (
                  <Pill tone="ok">
                    {t("The test message to {name} went out at {when}.", {
                      name: tested.name,
                      when: absoluteTime(testOutcome.delivery.sent_at),
                    })}
                  </Pill>
                )
                : (
                  <Pill tone="error">
                    {t("The test to {name} failed: {reason}", {
                      name: tested.name,
                      reason: deliveryWords(t, testOutcome.delivery),
                    })}
                  </Pill>
                )
            )}
          >
            {!loaded && <Bones rows={4} height={18} />}
            {loaded && items.length === 0 && (
              <Empty
                icon="notifications"
                action={canManage && !editing && (
                  <Button kind="quiet" onClick={newChannel} testId="new-channel-empty">{t("New channel")}</Button>
                )}
              >
                {t("No channels: the alerts fire and the campaigns end, but nobody is told outside the panel.")}
              </Empty>
            )}
            {loaded && items.length > 0 && (
              <Table
                rows={items}
                keyOf={(one) => one.id}
                rowTestId={(one) => `channel-${one.id}`}
                testId="channels"
                columns={channelColumns}
              />
            )}
          </Card>
        ),
        shape: (
          <Card
            title={t("What the queue is made of")}
            note={t("Counted over the rows this filter read, not over the whole month.")}
          >
            <Band segments={queueStates} testId="queue-states" />
          </Card>
        ),
        queue: (
          <Card
            title={t("Delivery queue")}
            flush
            note={t("One row per event and channel, newest first. A receiver that is down delays a message rather than losing it: the row waits, the attempts are counted on it, and a message nobody received ends as a dead letter an operator sends again.")}
            bar={
              <Toolbar
                end={<Download path="/api/v1/notifications/deliveries" params={logParams} />}
              >
                <select
                  value={logFilter.channel}
                  onChange={(event) => setLogFilter({ ...logFilter, channel: event.target.value })}
                  aria-label={t("Channel")}
                  data-testid="filter-channel"
                >
                  <option value="">{t("every channel")}</option>
                  {items.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
                </select>
                <select
                  value={logFilter.status}
                  onChange={(event) => setLogFilter({ ...logFilter, status: event.target.value })}
                  aria-label={t("State")}
                  data-testid="filter-state"
                >
                  <option value="">{t("every state")}</option>
                  <option value="sent">{t("sent")}</option>
                  <option value="failed">{t("failed")}</option>
                  {states.map((state) => <option key={state} value={state}>{stateWords(t, state)}</option>)}
                </select>
                <select
                  value={logFilter.window}
                  onChange={(event) => setLogFilter({ ...logFilter, window: event.target.value as LogWindow })}
                  aria-label={t("When")}
                  data-testid="filter-window"
                >
                  <option value="1">{t("last hour")}</option>
                  <option value="24">{t("last 24 hours")}</option>
                  <option value="168">{t("last 7 days")}</option>
                  <option value="">{t("the whole month")}</option>
                </select>
              </Toolbar>
            }
            foot={queueRead
              ? t("{n} rows read", { n: rows.length })
              : undefined}
          >
            {deliveries.error
              ? <Problem>{errorText(deliveries.error)}</Problem>
              : (
                <Table
                  rows={rows}
                  keyOf={(one) => one.id}
                  rowTestId={(one) => `delivery-${one.id}`}
                  testId="deliveries"
                  loading={!queueRead}
                  empty={items.length === 0 && loaded
                    ? t("Nothing has been sent yet: there is no channel to send to.")
                    : t("No delivery matches the filter.")}
                  columns={deliveryColumns}
                />
              )}
          </Card>
        ),
      }} />
    </>
  );
}

/** What a channel last managed to do, as the state it ended in and when. */
function LastDelivery({ last }: { last?: DeliverySummary | null }) {
  const t = useT();
  if (!last) return <span className="fl-faint">{t("nothing sent yet")}</span>;
  const when = last.at || last.sent_at || "";
  return (
    <TwoLine sub={last.error_code || undefined}>
      <Pill tone={stateTone(last.state)}>{stateWords(t, last.state)}</Pill>
      {when && <span title={absoluteTime(when)}> {relativeTime(when)}</span>}
    </TwoLine>
  );
}

/**
 * A decision that needs a sentence for the trail before it is taken.
 *
 * The reason is not politeness: it is what the audit trail keeps beside
 * the change, and the server refuses a write without one.
 */
function ReasonModal({ title, body, confirm, danger = false, busy, onClose, onConfirm }: {
  title: string;
  body: string;
  confirm: string;
  danger?: boolean;
  busy: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const ready = reason.trim().length >= 8;
  return (
    <Modal
      title={title}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind={danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason.trim())}
            testId="confirm-reason"
          >
            {busy ? t("Saving…") : confirm}
          </Button>
        </>
      }
    >
      <p>{body}</p>
      <Fields>
        <Field label={t("Reason")} hint={t("At least 8 characters; it stays in the audit trail.")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
        </Field>
      </Fields>
    </Modal>
  );
}

/**
 * The fields of a channel: the kind chooses which address fields show, the
 * events are ticked from the catalogue the server sent, and the filter
 * narrows by severity, site and environment.
 */
function ChannelFields({ form, subjects, severities, onChange }: {
  form: ChannelForm; subjects: Subject[]; severities: string[]; onChange: (form: ChannelForm) => void;
}) {
  const t = useT();
  const set = (patch: Partial<ChannelForm>) => onChange({ ...form, ...patch });
  const toggleEvent = (name: string) => set({
    events: form.events.includes(name) ? form.events.filter((event) => event !== name) : [...form.events, name],
  });
  const fields = (
    <Fields>
      <Field label={t("Name")}>
        <input value={form.name} onChange={(event) => set({ name: event.target.value })} data-testid="channel-name" />
      </Field>
      <Field label={t("Kind")}>
        <select value={form.kind} onChange={(event) => set({ kind: event.target.value as ChannelKind })}
                data-testid="channel-kind">
          <option value="webhook">{kindLabel(t, "webhook")}</option>
          <option value="slack_webhook">{kindLabel(t, "slack_webhook")}</option>
          <option value="email">{kindLabel(t, "email")}</option>
        </select>
      </Field>

      {form.kind !== "email" && (
        <Field
          label={t("Address")}
          wide
          hint={form.kind === "webhook"
            ? t("The deliveries are JSON, signed with HMAC-SHA256 over the body and the timestamp like the webhook of the environment file.")
            : form.urlSet
              ? secretWords(t, form, t("URL is set; leave the field empty to keep it, or type a new one. The address is the credential of the channel and is never shown back."))
              : t("An incoming webhook of Slack, or of a service that reads its shape: the body is {text, blocks}.")}
        >
          <input value={form.url} onChange={(event) => set({ url: event.target.value })}
                 placeholder={form.urlSet ? t("URL is set") : "https://"} data-testid="channel-url" />
        </Field>
      )}
      {form.kind === "webhook" && (
        <Field
          label={t("Signing secret")}
          wide
          hint={secretWords(t, form, t("Required: the receiver verifies the signature, and an empty key signs nothing."))}
        >
          <input type="password" autoComplete="new-password" value={form.secret}
                 onChange={(event) => set({ secret: event.target.value })} data-testid="channel-secret" />
        </Field>
      )}
      {form.kind === "email" && (
        <>
          <Field label={t("Mail relay host")}>
            <input value={form.host} onChange={(event) => set({ host: event.target.value })} data-testid="channel-host" />
          </Field>
          <Field label={t("Port")}>
            <input type="number" min={1} max={65535} value={form.port}
                   onChange={(event) => set({ port: event.target.value })} data-testid="channel-port" />
          </Field>
          <Field label={t("From")}>
            <input value={form.from} onChange={(event) => set({ from: event.target.value })}
                   placeholder="flotestro@example.com" data-testid="channel-from" />
          </Field>
          <Field label={t("Recipients")} hint={t("One per line or comma-separated; at most twenty.")}>
            <textarea rows={3} value={form.to} onChange={(event) => set({ to: event.target.value })}
                      data-testid="channel-to" />
          </Field>
          <Field label={t("Username")} hint={t("Empty means the relay takes mail without a login.")}>
            <input value={form.username} onChange={(event) => set({ username: event.target.value })}
                   autoComplete="off" data-testid="channel-username" />
          </Field>
          <Field label={t("Password secret")}
                 hint={t("The name of a secret of the secret store; the password itself is never written here.")}>
            <input value={form.passwordSecret} onChange={(event) => set({ passwordSecret: event.target.value })}
                   data-testid="channel-password-secret" />
          </Field>
        </>
      )}

      <Field label={t("Least severity")}
             hint={t("Alerts below it are not carried; the other events have no severity and pass.")}>
        <select value={form.severityMin} onChange={(event) => set({ severityMin: event.target.value })}
                data-testid="channel-severity">
          <option value="">{t("every severity")}</option>
          {severities.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
        </select>
      </Field>
      <Field label={t("Site")} hint={t("Empty means every site; an event that names no host passes.")}>
        <input value={form.site} onChange={(event) => set({ site: event.target.value })} data-testid="channel-site" />
      </Field>
      <Field label={t("Environment")}>
        <input value={form.environment} onChange={(event) => set({ environment: event.target.value })}
               data-testid="channel-environment" />
      </Field>
      <Field label={t("Reason or change reference")} wide hint={t("Kept in the audit trail with the channel.")}>
        <input value={form.reason} onChange={(event) => set({ reason: event.target.value })}
               data-testid="channel-reason" />
      </Field>
    </Fields>
  );

  /* A tick box carries its own sentence, so it stands beside the fields
     rather than inside one: a label wrapped in a label has two targets
     and the browser picks whichever it likes. */
  return (
    <Stack>
      {fields}
      <Stack>
        <Note>{t("Events")}</Note>
        {subjects.length === 0
          ? <Note>{t("The server named no events this installation can carry.")}</Note>
          : subjects.map((subject) => (
            <Check key={subject.name} checked={form.events.includes(subject.name)}
                   onChange={() => toggleEvent(subject.name)}>
              <code>{subject.name}</code> {subject.description}
            </Check>
          ))}
      </Stack>
      <Row>
        {form.kind === "email" && (
          <Check checked={form.starttls} onChange={(on) => set({ starttls: on })}>
            {t("STARTTLS (required for a login)")}
          </Check>
        )}
        <Check checked={form.enabled} onChange={(on) => set({ enabled: on })}>{t("enabled")}</Check>
      </Row>
    </Stack>
  );
}

export const NOTIFICATIONS_SCREEN = "next_notifications";

export const NOTIFICATIONS: BoardEntry[] = [
  { key: "channels_count", title: "Channels", width: 3, height: 1 },
  { key: "carrying", title: "Carrying events", width: 3, height: 1 },
  { key: "dead", title: "Dead letters", width: 3, height: 1 },
  { key: "shape", title: "What the queue is made of", width: 3, height: 1 },
  { key: "form", title: "The channel being written", width: 12, height: 5 },
  { key: "channels", title: "Channels", width: 12, height: 4 },
  { key: "queue", title: "Delivery queue", width: 12, height: 6 },
];
