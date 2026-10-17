import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Notifications, addressWithheld, canRetry, channelBody, deliveryParams, deliveryWords,
  describeChannel, describeFilter, emptyForm, formOf, nextAttemptAt, recipients, stateTone,
  stateWords, type Channel, type Delivery,
} from "./Notifications";
import { ToastProvider } from "../../components/Toast";

/**
 * What this screen must not say.
 *
 * A dead letter nobody has counted is not a count of none, so the
 * headline is an em dash until the queue has answered. A credential is
 * never served back, so the address of an incoming webhook reads as "URL
 * is set" and never as a URL. And every write carries a reason, because
 * the audit trail keeps the sentence beside the change - a dialog that
 * takes the decision without one is a change nobody can account for.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

/** A path held open: the query never settles, so the card is still waiting. */
const PENDING = Symbol("pending");

/** What the server is made to refuse for one test. */
const mood: { refuse: string | null } = { refuse: null };

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    if (answers[key] === PENDING) return new Promise(() => {});
    if (answers[key] instanceof actual.ApiError) return Promise.reject(answers[key]);
    return Promise.resolve(answers[key]);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        if (mood.refuse && path.includes(mood.refuse)) {
          return Promise.reject(new actual.ApiError(409, "conflict", "the receiver is gone"));
        }
        return Promise.resolve({ id: "d9", state: "delivered", status: "sent", sent_at: "2026-10-16T09:00:00Z" });
      },
      put: (path: string, body?: unknown) => {
        sent.push({ method: "PUT", path, body });
        const record = body as { name: string; enabled: boolean };
        return Promise.resolve({ ...record, id: "c1" });
      },
      del: (path: string, body?: unknown) => {
        sent.push({ method: "DELETE", path, body });
        return Promise.resolve(undefined);
      },
    },
  };
});

const manager = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["notification.manage"] };
const reader = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["notification.read"] };

const channel = (over: Partial<Channel> = {}): Channel => ({
  id: "c1",
  name: "ops webhook",
  kind: "webhook",
  config: { url: "https://ops.example.com/hook", secret_set: true },
  secret_configured: true,
  events: ["alert.fired"],
  filter: { severity_min: "warning" },
  enabled: true,
  created_by: "tszymanski",
  reason: "the first channel",
  created_at: "2026-10-16T07:00:00Z",
  updated_at: "2026-10-16T07:00:00Z",
  last_delivery: { id: "d1", state: "delivered", at: "2026-10-16T08:00:00Z" },
  ...over,
});

const delivery = (over: Partial<Delivery> = {}): Delivery => ({
  id: "d1",
  channel_id: "c1",
  channel_name: "ops webhook",
  event_id: 41,
  event_type: "alert.fired",
  state: "delivered",
  attempt: 1,
  next_attempt_at: "",
  last_error_code: "",
  last_error: "",
  created_at: "2026-10-16T08:00:00Z",
  updated_at: "2026-10-16T08:00:00Z",
  status: "sent",
  error_code: "",
  error: "",
  sent_at: "2026-10-16T08:00:00Z",
  ...over,
});

function serve(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/whoami": manager,
    "/api/v1/notifications/channels": {
      items: [channel()], count: 1,
      kinds: ["webhook", "email", "slack_webhook"],
      subjects: [{ name: "alert.fired", description: "an alert began" }],
      severities: ["info", "warning", "critical"],
      states: ["pending", "delivered", "dead_letter"],
    },
    "/api/v1/notifications/deliveries": { items: [delivery()], count: 1, dead_letters: 0 },
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    ...over,
  });
}

/**
 * The screen, on the sub-tab asked for.
 *
 * The queue and the form of a channel are sub-tabs since 17.10 and the
 * sub-tab is in the address, so a test that reads the queue opens the
 * screen where the queue is - the same address a colleague would be sent.
 */
function draw(tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const at = tab === "" ? "/notifications" : `/notifications?tab=${tab}`;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Notifications />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  mood.refuse = null;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the channels", () => {
  it("names each one, what it is, where it goes and what it last managed", async () => {
    serve();
    draw();
    const row = await screen.findByTestId("channel-c1");
    expect(row).toHaveTextContent("ops webhook");
    expect(row).toHaveTextContent("Webhook (signed)");
    expect(row).toHaveTextContent("https://ops.example.com/hook");
    expect(row).toHaveTextContent("alert.fired");
    expect(row).toHaveTextContent("severity ≥ warning");
    expect(within(row).getByText("sent")).toHaveClass("fl-pill", "fl-ok");
  });

  it("never shows back the address of an incoming webhook, because it is the credential", async () => {
    serve({
      "/api/v1/notifications/channels": {
        items: [channel({ id: "c2", name: "slack", kind: "slack_webhook", config: { url_set: true } })],
        count: 1, kinds: [], subjects: [], severities: [], states: [],
      },
    });
    draw();
    const row = await screen.findByTestId("channel-c2");
    expect(row).toHaveTextContent("URL is set");
    expect(row).not.toHaveTextContent("https://");
  });

  it("says a channel that has carried nothing has carried nothing, not that it failed", async () => {
    serve({
      "/api/v1/notifications/channels": {
        items: [channel({ last_delivery: null })], count: 1, kinds: [], subjects: [], severities: [], states: [],
      },
    });
    draw();
    const row = await screen.findByTestId("channel-c1");
    expect(within(row).getByText("nothing sent yet")).toBeInTheDocument();
  });

  it("offers a reader with no right to manage nothing to press", async () => {
    serve({ "/api/v1/whoami": reader });
    draw();
    await screen.findByTestId("channel-c1");
    expect(screen.queryByTestId("new-channel")).toBeNull();
    expect(screen.queryByTestId("test-c1")).toBeNull();
    expect(screen.queryByTestId("delete-c1")).toBeNull();
  });

  it("says who may not read them at all rather than drawing an empty screen", async () => {
    const { ApiError } = await import("../../lib/api");
    serve({ "/api/v1/notifications/channels": new ApiError(403, "forbidden", "no") });
    draw();
    await waitFor(() => expect(screen.getByText(
      "You may not read the notification channels of this installation.",
    )).toBeInTheDocument());
  });

  it("offers the way to make one where there are none", async () => {
    serve({
      "/api/v1/notifications/channels": { items: [], count: 0, kinds: [], subjects: [], severities: [], states: [] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-channel-empty")).toBeInTheDocument());
    expect(screen.getByText(
      "No channels: the alerts fire and the campaigns end, but nobody is told outside the panel.",
    )).toBeInTheDocument();
  });
});

describe("what nobody has counted", () => {
  it("draws an em dash for the dead letters until the queue has answered, never a nought", async () => {
    serve({ "/api/v1/notifications/deliveries": PENDING });
    draw();
    await screen.findByTestId("channel-c1");
    const tile = screen.getByTestId("kpi-Dead letters");
    expect(tile).toHaveAttribute("data-state", "unknown");
    expect(tile).toHaveTextContent("—");
    expect(tile).not.toHaveTextContent("0");
  });

  it("counts the installation's dead letters and not the page's", async () => {
    serve({
      "/api/v1/notifications/deliveries": {
        items: [delivery()], count: 1, dead_letters: 4,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Dead letters")).toHaveTextContent("4"));
    expect(screen.getByTestId("kpi-Dead letters")).toHaveAttribute("data-state", "error");
  });

  it("says how many channels there are only once the list has arrived", async () => {
    serve({ "/api/v1/notifications/channels": PENDING });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Channels")).toHaveAttribute("data-state", "unknown"));
    expect(screen.getByTestId("kpi-Channels")).toHaveTextContent("Channels: unknown");
  });
});

describe("the queue", () => {
  it("puts the filter to the server rather than sieving a page it already has", async () => {
    serve();
    draw("queue");
    await screen.findByTestId("delivery-d1");
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-state"), { target: { value: "dead_letter" } });
    await waitFor(() => expect(asked.some((one) => one.includes("state=dead_letter"))).toBe(true));
    fireEvent.change(screen.getByTestId("filter-channel"), { target: { value: "c1" } });
    await waitFor(() => expect(asked.some((one) => one.includes("channel_id=c1"))).toBe(true));
  });

  it("offers a dead letter back to the queue and nothing else", async () => {
    serve({
      "/api/v1/notifications/deliveries": {
        items: [delivery(), delivery({ id: "d2", state: "dead_letter", last_error_code: "http_502", last_error: "bad gateway" })],
        count: 2, dead_letters: 1,
      },
    });
    draw("queue");
    await screen.findByTestId("delivery-d2");
    expect(screen.queryByTestId("retry-d1")).toBeNull();
    fireEvent.click(screen.getByTestId("retry-d2"));
    await waitFor(() => expect(sent).toContainEqual({
      method: "POST", path: "/api/v1/notifications/deliveries/d2/retry", body: undefined,
    }));
  });

  it("says a row with nothing due has nothing due, with a dash and not a date", async () => {
    serve({
      "/api/v1/notifications/deliveries": {
        items: [delivery({ id: "d3", state: "suppressed", next_attempt_at: "2026-10-16T09:00:00Z" })],
        count: 1, dead_letters: 0,
      },
    });
    draw("queue");
    const row = await screen.findByTestId("delivery-d3");
    expect(within(row).getAllByText("kept back")[0]).toHaveClass("fl-pill");
    expect(within(row).getAllByText("—").length).toBeGreaterThan(0);
  });

  it("says there is nothing to send to when there is no channel at all", async () => {
    serve({
      "/api/v1/notifications/channels": { items: [], count: 0, kinds: [], subjects: [], severities: [], states: [] },
      "/api/v1/notifications/deliveries": { items: [], count: 0, dead_letters: 0 },
    });
    draw("queue");
    await waitFor(() => expect(screen.getByText(
      "Nothing has been sent yet: there is no channel to send to.",
    )).toBeInTheDocument());
  });
});

describe("writing a channel", () => {
  it("refuses a webhook with no signing secret and says why", async () => {
    serve();
    draw();
    await screen.findByTestId("channel-c1");
    fireEvent.click(screen.getByTestId("new-channel"));
    fireEvent.change(await screen.findByTestId("channel-name"), { target: { value: "pager" } });
    fireEvent.change(screen.getByTestId("channel-url"), { target: { value: "https://pager.example.com/x" } });
    fireEvent.change(screen.getByTestId("channel-reason"), { target: { value: "paging the duty operator" } });
    expect(screen.getByTestId("save-channel")).toBeDisabled();
    expect(screen.getByText(
      "a webhook needs a signing secret; a delivery signed with an empty key is one anybody can forge",
    )).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("channel-secret"), { target: { value: "s3cret" } });
    await waitFor(() => expect(screen.getByTestId("save-channel")).toBeEnabled());
    fireEvent.click(screen.getByTestId("save-channel"));
    await waitFor(() => expect(sent[0]?.path).toBe("/api/v1/notifications/channels"));
    expect(sent[0]?.method).toBe("POST");
    expect(sent[0]?.body).toMatchObject({
      name: "pager", kind: "webhook", config: { url: "https://pager.example.com/x", secret: "s3cret" },
      reason: "paging the duty operator",
    });
  });

  it("writes an edit back to the channel it came from", async () => {
    serve();
    draw();
    await screen.findByTestId("channel-c1");
    fireEvent.click(screen.getByTestId("edit-c1"));
    fireEvent.change(await screen.findByTestId("channel-name"), { target: { value: "ops webhook two" } });
    fireEvent.click(screen.getByTestId("save-channel"));
    await waitFor(() => expect(sent[0]?.path).toBe("/api/v1/notifications/channels/c1"));
    expect(sent[0]?.method).toBe("PUT");
    // The stored secret is kept rather than sent back empty.
    expect(sent[0]?.body).toMatchObject({ name: "ops webhook two", config: { secret_set: true } });
  });
});

describe("a decision", () => {
  it("takes a reason before it disables a channel, and flips only the flag", async () => {
    serve();
    draw();
    await screen.findByTestId("channel-c1");
    fireEvent.click(screen.getByTestId("toggle-c1"));
    const confirm = await screen.findByTestId("confirm-reason");
    // Eight characters is the trail's own floor; less is not a reason.
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "receiver retired" } });
    await waitFor(() => expect(confirm).toBeEnabled());
    fireEvent.click(confirm);
    await waitFor(() => expect(sent[0]?.method).toBe("PUT"));
    expect(sent[0]?.path).toBe("/api/v1/notifications/channels/c1");
    expect(sent[0]?.body).toMatchObject({ enabled: false, reason: "receiver retired" });
  });

  it("takes a reason before it deletes one, and sends it with the removal", async () => {
    serve();
    draw();
    await screen.findByTestId("channel-c1");
    fireEvent.click(screen.getByTestId("delete-c1"));
    await screen.findByTestId("confirm-reason");
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "replaced by the pager" } });
    fireEvent.click(screen.getByTestId("confirm-reason"));
    await waitFor(() => expect(sent[0]?.method).toBe("DELETE"));
    expect(sent[0]?.path).toBe("/api/v1/notifications/channels/c1");
    expect(sent[0]?.body).toEqual({ reason: "replaced by the pager" });
  });

  it("leaves what the server refused on the screen, not only in a toast", async () => {
    serve({
      "/api/v1/notifications/deliveries": {
        items: [delivery({ id: "d2", state: "dead_letter" })], count: 1, dead_letters: 1,
      },
    });
    mood.refuse = "/retry";
    draw("queue");
    await screen.findByTestId("delivery-d2");
    fireEvent.click(screen.getByTestId("retry-d2"));
    // A toast says it once and goes; a write that failed is a fact about
    // the installation until somebody has dealt with it.
    await waitFor(() => expect(document.querySelector(".fl-banner")).toHaveTextContent("the receiver is gone"));
  });

  it("sends a test and says on the screen what came of it", async () => {
    serve();
    draw();
    await screen.findByTestId("channel-c1");
    fireEvent.click(screen.getByTestId("test-c1"));
    await waitFor(() => expect(sent[0]?.path).toBe("/api/v1/notifications/channels/c1/test"));
    await waitFor(() => expect(screen.getByText(/The test message to ops webhook went out/)).toBeInTheDocument());
  });
});

describe("the words and the shapes", () => {
  it("keeps a refusal apart from a success and from a thing still waiting", () => {
    expect(stateTone("delivered")).toBe("ok");
    expect(stateTone("dead_letter")).toBe("error");
    expect(stateTone("retry_wait")).toBe("warn");
    // A row nobody has a colour for is unknown, never well.
    expect(stateTone("leased")).toBe("unknown");
    expect(stateWords((text) => text, "retry_wait")).toBe("waiting to retry");
  });

  it("gives a next attempt only to a row that has one", () => {
    expect(nextAttemptAt({ state: "retry_wait", next_attempt_at: "2026-10-16T09:00:00Z" }))
      .toBe("2026-10-16T09:00:00Z");
    expect(nextAttemptAt({ state: "delivered", next_attempt_at: "2026-10-16T09:00:00Z" })).toBe("");
    expect(nextAttemptAt({ state: "suppressed", next_attempt_at: "2026-10-16T09:00:00Z" })).toBe("");
    expect(canRetry({ state: "dead_letter" })).toBe(true);
    expect(canRetry({ state: "pending" })).toBe(false);
  });

  it("turns the screen's filter into the server's query", () => {
    const now = new Date("2026-10-16T10:00:00Z");
    expect(deliveryParams({ channel: "c1", status: "sent", window: "1" }, now).toString())
      .toBe(new URLSearchParams({
        channel_id: "c1", status: "sent", since: "2026-10-16T09:00:00.000Z",
      }).toString());
    // A state of the queue goes as a state; the two older words go as a status.
    expect(deliveryParams({ channel: "", status: "dead_letter", window: "" }, now).get("state")).toBe("dead_letter");
    expect(deliveryParams({ channel: "", status: "", window: "" }, now).toString()).toBe("");
  });

  it("refuses a form that is not a channel, and says which field it is", () => {
    expect(channelBody({ ...emptyForm(), name: "" }).problem).toBe("name");
    expect(channelBody({ ...emptyForm(), name: "x", events: [] }).problem).toBe("events");
    expect(channelBody({ ...emptyForm(), name: "x", url: "ftp://x" }).problem).toBe("url");
    expect(channelBody({ ...emptyForm(), name: "x", url: "https://x", secret: "k", reason: "short" }).problem)
      .toBe("reason");
    const mail = {
      ...emptyForm("email"), name: "x", host: "smtp", from: "a@b", to: "c@d",
      username: "u", passwordSecret: "", reason: "a long enough reason",
    };
    expect(channelBody(mail).problem).toBe("auth_secret");
    expect(channelBody({ ...mail, passwordSecret: "p", starttls: false }).problem).toBe("auth_tls");
    expect(channelBody({ ...mail, passwordSecret: "p" }).body).toMatchObject({
      config: { host: "smtp", port: 587, to: ["c@d"] },
    });
  });

  it("reads the recipients however they were typed", () => {
    expect(recipients(" a@b \n c@d, e@f ; ")).toEqual(["a@b", "c@d", "e@f"]);
  });

  it("describes a channel and its filter in one line each", () => {
    expect(describeChannel({ kind: "webhook", config: { url: "https://x/y" } })).toBe("https://x/y");
    expect(describeChannel({ kind: "email", config: { to: ["a@b"], host: "smtp", port: 587 } }))
      .toBe("a@b via smtp:587 (STARTTLS)");
    expect(describeFilter((text) => text, undefined)).toBe("whole fleet");
    expect(describeFilter((text) => text, { site: "lab" })).toBe("site=lab");
    expect(addressWithheld({ kind: "slack_webhook", config: { url_set: true } })).toBe(true);
    expect(addressWithheld({ kind: "webhook", config: { url: "https://x" } })).toBe(false);
  });

  it("reads a stored channel back into a form without its credential", () => {
    const form = formOf(channel());
    expect(form.secret).toBe("");
    expect(form.secretSet).toBe(true);
    expect(form.name).toBe("ops webhook");
  });

  it("says what came of a delivery in the words of the screen", () => {
    const t = (text: string) => text;
    expect(deliveryWords(t, { state: "delivered" })).toBe("sent");
    expect(deliveryWords(t, { state: "suppressed", last_error: "silenced" })).toBe("silenced");
    expect(deliveryWords(t, { state: "dead_letter", last_error_code: "http_502", last_error: "bad gateway" }))
      .toBe("http_502: bad gateway");
    expect(deliveryWords(t, { state: "dead_letter" })).toBe("failed");
  });
});
