import { describe, expect, it } from "vitest";
import {
  addressWithheld, channelBody, deliveryParams, deliveryWords, describeChannel, describeFilter, emptyForm, formOf, recipients,
  type Channel,
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
