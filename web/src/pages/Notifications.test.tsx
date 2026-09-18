import { describe, expect, it } from "vitest";
import {
  addressWithheld, canRetry, channelBody, deliveryParams, deliveryWords, describeChannel, describeFilter,
  emptyForm, formOf, nextAttemptAt, recipients, secretWords, stateTone, stateWords,
  type Channel, type Delivery,
} from "./Notifications";

/* The page sends what these helpers build and shows what they say: the
   body of a channel with the server's own checks made first, the words
   of a delivery, the query of the log. They are pure, so every branch
   is checked here without a screen. */

const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (_, key: string) => String(params?.[key] ?? `{${key}}`));

const stored: Channel = {
  id: "c1", name: "on-call", kind: "webhook",
  config: { url: "https://hooks.example.com/flotestro", secret_set: true },
  events: ["alert.fired"], filter: { severity_min: "warning", site: "krakow" },
  enabled: true, created_by: "admin", reason: "the on-call receiver",
  created_at: "2026-09-15T10:00:00Z", updated_at: "2026-09-15T10:00:00Z",
};

describe("channelBody", () => {
  it("names what stops a form from being a channel, in the order the server checks", () => {
    expect(channelBody({ ...emptyForm(), reason: "a proper reason" }).problem).toBe("name");
    expect(channelBody({ ...emptyForm(), name: "x", events: [] }).problem).toBe("events");
    expect(channelBody({ ...emptyForm(), name: "x", url: "ftp://x" }).problem).toBe("url");
    expect(channelBody({ ...emptyForm(), name: "x", url: "https://x" }).problem).toBe("reason");
    const mail = { ...emptyForm("email"), name: "x", reason: "a proper reason" };
    expect(channelBody(mail).problem).toBe("host");
    expect(channelBody({ ...mail, host: "relay", port: "70000" }).problem).toBe("port");
    expect(channelBody({ ...mail, host: "relay", from: "nobody" }).problem).toBe("from");
    expect(channelBody({ ...mail, host: "relay", from: "a@b", to: "" }).problem).toBe("to");
    expect(channelBody({ ...mail, host: "relay", from: "a@b", to: "x@y", username: "u" }).problem).toBe("auth_secret");
    expect(channelBody({ ...mail, host: "relay", from: "a@b", to: "x@y", username: "u", passwordSecret: "p", starttls: false }).problem).toBe("auth_tls");
  });

  it("builds the body of a mailbox with the recipients as a list and the login only when given", () => {
    const { body } = channelBody({
      ...emptyForm("email"), name: "ops", reason: "the ops mailbox", host: "relay.example.com", port: "25",
      starttls: false, from: "panel@example.com", to: "a@example.com, b@example.com\n", events: ["host.offline"],
      severityMin: "critical", site: " krakow ",
    });
    expect(body).toEqual({
      name: "ops", kind: "email", events: ["host.offline"], enabled: true, reason: "the ops mailbox",
      filter: { severity_min: "critical", site: "krakow" },
      config: {
        host: "relay.example.com", port: 25, starttls: false, from: "panel@example.com",
        to: ["a@example.com", "b@example.com"], username: undefined, password_secret: undefined,
      },
    });
  });

  it("keeps a stored webhook secret unless a new one is typed or the stored one is cleared", () => {
    const form = { ...formOf(stored), reason: "edited the address" };
    expect(channelBody(form).body?.config).toEqual({ url: "https://hooks.example.com/flotestro", secret_set: true });
    expect(channelBody({ ...form, secret: "fresh" }).body?.config).toEqual({ url: "https://hooks.example.com/flotestro", secret: "fresh" });
    expect(channelBody({ ...form, keepSecret: false }).body?.config).toEqual({ url: "https://hooks.example.com/flotestro" });
  });

  it("keeps the withheld address of an incoming webhook unless a new one is typed", () => {
    const slack: Channel = { ...stored, kind: "slack_webhook", config: { url_set: true } };
    const form = { ...formOf(slack), reason: "edited the events" };
    expect(form.url).toBe("");
    expect(form.urlSet).toBe(true);
    expect(channelBody(form).body?.config).toEqual({ url_set: true });
    expect(channelBody({ ...form, url: "https://hooks.example.com/T0/B0/new" }).body?.config)
      .toEqual({ url: "https://hooks.example.com/T0/B0/new" });
    // A new channel has nothing stored to keep, so an empty address is a problem.
    expect(channelBody({ ...emptyForm("slack_webhook"), name: "x", reason: "a proper reason" }).problem).toBe("url");
    expect(addressWithheld(slack)).toBe(true);
    expect(addressWithheld(stored)).toBe(false);
  });
});

describe("formOf", () => {
  it("reads a stored channel back into the form without its secret", () => {
    const form = formOf(stored);
    expect(form.secret).toBe("");
    expect(form.secretSet).toBe(true);
    expect(form.severityMin).toBe("warning");
    expect(form.site).toBe("krakow");
    expect(form.events).toEqual(["alert.fired"]);
  });

  it("reads a mailbox with its recipients one per line", () => {
    const form = formOf({ ...stored, kind: "email", config: { host: "relay", port: 25, starttls: false, from: "a@b", to: ["x@y", "z@w"] } });
    expect(form.host).toBe("relay");
    expect(form.port).toBe("25");
    expect(form.starttls).toBe(false);
    expect(form.to).toBe("x@y\nz@w");
  });
});

describe("the words of the table", () => {
  it("describes an address by kind and a filter by what it keeps", () => {
    expect(describeChannel(stored)).toBe("https://hooks.example.com/flotestro");
    expect(describeChannel({ kind: "email", config: { host: "relay", port: 587, starttls: true, to: ["a@b"] } })).toBe("a@b via relay:587 (STARTTLS)");
    expect(describeFilter(t, stored.filter)).toBe("severity ≥ warning, site=krakow");
    expect(describeFilter(t, {})).toBe("whole fleet");
  });

  it("reads a delivery as sent, or as its typed failure", () => {
    expect(deliveryWords(t, { status: "sent", error_code: "", error: "" })).toBe("sent");
    expect(deliveryWords(t, { status: "failed", error_code: "connection_refused", error: "dial tcp: connection refused" })).toBe("connection_refused: dial tcp: connection refused");
    expect(deliveryWords(t, { status: "failed", error_code: "timeout", error: "" })).toBe("timeout");
  });

  it("splits the recipients at lines, commas and semicolons", () => {
    expect(recipients(" a@b,\nc@d; e@f ")).toEqual(["a@b", "c@d", "e@f"]);
  });
});

describe("deliveryParams", () => {
  const now = new Date("2026-09-15T12:00:00Z");

  it("puts the filter in the query and turns the window into a moment", () => {
    const params = deliveryParams({ channel: "c1", status: "failed", window: "24" }, now);
    expect(params.get("channel_id")).toBe("c1");
    expect(params.get("status")).toBe("failed");
    expect(params.get("since")).toBe("2026-09-14T12:00:00.000Z");
  });

  it("asks for the whole log when nothing narrows it", () => {
    expect(deliveryParams({ channel: "", status: "", window: "" }, now).toString()).toBe("");
  });
});

/* The queue is what the second half of the screen shows: a row per event
   and channel, with its state, its attempts and what refused it last.
   These check the words that table is built out of. */

const row: Delivery = {
  id: "d1", channel_id: "c1", channel_name: "on-call", event_id: 42, event_type: "alert.fired",
  title: "cpu_percent > 90 on web-01", state: "retry_wait", attempt: 3,
  next_attempt_at: "2026-09-15T12:04:00Z", last_error_code: "receiver_status",
  last_error: "the receiver answered 503", created_at: "2026-09-15T12:00:00Z",
  updated_at: "2026-09-15T12:02:00Z", status: "failed", error_code: "receiver_status",
  error: "the receiver answered 503", sent_at: "2026-09-15T12:02:00Z",
};

describe("the queue", () => {
  it("names every state and colours the ones an operator has to act on", () => {
    expect(stateWords(t, "delivered")).toBe("sent");
    expect(stateWords(t, "retry_wait")).toBe("waiting to retry");
    expect(stateWords(t, "dead_letter")).toBe("dead letter");
    expect(stateWords(t, "suppressed")).toBe("kept back");
    // A state the panel does not know is shown as it came rather than hidden.
    expect(stateWords(t, "something_new")).toBe("something_new");
    expect(stateTone("delivered")).toBe("ok");
    expect(stateTone("dead_letter")).toBe("error");
    expect(stateTone("retry_wait")).toBe("warn");
    expect(stateTone("pending")).toBe("unknown");
  });

  it("offers the retry button on a dead letter alone", () => {
    expect(canRetry({ ...row, state: "dead_letter" })).toBe(true);
    // A row the worker still has in hand is not an operator's to restart.
    for (const state of ["pending", "leased", "retry_wait", "delivered", "suppressed"] as const) {
      expect(canRetry({ ...row, state })).toBe(false);
    }
  });

  it("names the next attempt only for a row that has one", () => {
    expect(nextAttemptAt(row)).toBe("2026-09-15T12:04:00Z");
    expect(nextAttemptAt({ ...row, state: "pending" })).toBe("2026-09-15T12:04:00Z");
    // A dead letter's next_attempt_at is whatever it was when the attempts
    // ran out; showing it would read as a promise the queue does not make.
    expect(nextAttemptAt({ ...row, state: "dead_letter" })).toBe("");
    expect(nextAttemptAt({ ...row, state: "delivered" })).toBe("");
    expect(nextAttemptAt({ ...row, state: "suppressed" })).toBe("");
  });

  it("reads the outcome from the state and the typed error of the row", () => {
    expect(deliveryWords(t, { ...row, state: "delivered" })).toBe("sent");
    expect(deliveryWords(t, row)).toBe("receiver_status: the receiver answered 503");
    expect(deliveryWords(t, { ...row, state: "dead_letter", last_error_code: "channel_credentials_rejected", last_error: "", error_code: "", error: "" }))
      .toBe("channel_credentials_rejected");
    expect(deliveryWords(t, { ...row, state: "suppressed", last_error_code: "", last_error: "silence until 2026-09-15T13:00:00Z: planned audit", error_code: "", error: "" }))
      .toBe("silence until 2026-09-15T13:00:00Z: planned audit");
    expect(deliveryWords(t, { ...row, state: "pending", last_error_code: "", last_error: "", error_code: "", error: "" })).toBe("failed");
  });

  it("narrows the log by either vocabulary: the old status or the queue's state", () => {
    const now = new Date("2026-09-15T12:00:00Z");
    expect(deliveryParams({ channel: "", status: "sent", window: "" }, now).toString()).toBe("status=sent");
    expect(deliveryParams({ channel: "", status: "dead_letter", window: "" }, now).toString()).toBe("state=dead_letter");
    expect(deliveryParams({ channel: "", status: "suppressed", window: "" }, now).get("status")).toBeNull();
  });
});

describe("the secret of a channel", () => {
  it("never shows the value, only that one is configured and when it was rotated", () => {
    const none = "nothing is configured";
    expect(secretWords(t, { secretSet: false, secretRotatedAt: "" }, none)).toBe(none);
    expect(secretWords(t, { secretSet: true, secretRotatedAt: "" }, none))
      .toBe("A secret is configured; leave the field empty to keep it, or type a new one.");
    const rotated = secretWords(t, { secretSet: true, secretRotatedAt: "2026-09-15T10:00:00Z" }, none);
    expect(rotated).toContain("last rotated");
    expect(rotated).toContain(new Date("2026-09-15T10:00:00Z").toLocaleString());
  });

  it("reads the channel's own flags rather than the configuration it no longer carries", () => {
    // The API of the queue release says it on the channel; the field in
    // the configuration is the same fact in the older shape.
    const fresh: Channel = {
      ...stored, config: { url: "https://hooks.example.com/flotestro" },
      secret_configured: true, secret_last_rotated_at: "2026-09-16T08:00:00Z",
    };
    const form = formOf(fresh);
    expect(form.secret).toBe("");
    expect(form.secretSet).toBe(true);
    expect(form.secretRotatedAt).toBe("2026-09-16T08:00:00Z");
    // And an empty field keeps what the store holds.
    expect(channelBody({ ...form, reason: "edited the events" }).body?.config)
      .toEqual({ url: "https://hooks.example.com/flotestro", secret_set: true });

    // An incoming webhook whose address is the credential is withheld on
    // the strength of the same flag.
    const slack: Channel = { ...stored, kind: "slack_webhook", config: {}, secret_configured: true };
    expect(addressWithheld(slack)).toBe(true);
    expect(formOf(slack).urlSet).toBe(true);
    expect(describeChannel({ ...slack, public_config: { display_host: "hooks.slack.com" } })).toBe("hooks.slack.com");
  });
});
