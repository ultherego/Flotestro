import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../components/Toast";
import {
  CertificateAuthority, CertificateAuthorityWarning, type FleetAuthority,
  authorityNote, authorityStateLabel, authorityTone, changeKey, reasonReady, refusalText,
} from "./CertificateAuthority";

/**
 * The fleet CA under /next.
 *
 * This is the root of trust of the whole installation, so what is checked
 * here is not that the section draws: it is what each write puts on the
 * wire, what a reader without the permission is not offered, how every
 * refusal the server can give reads, and that a row carries the three
 * facts an operator decides on - how many certificates hang on the
 * authority, what its state means for the next step, and which authority
 * it is.
 */

const read: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
const writes: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  const get = (path: string) => {
    read.push(path);
    const value = answers[path];
    if (value instanceof Error) return Promise.reject(value);
    if (value === undefined) {
      return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    }
    return Promise.resolve(value);
  };
  const write = (method: string) => (path: string, body?: unknown) => {
    sent.push({ method, path, body });
    // A DELETE carries its reason in the query, so the table is keyed by
    // the path without it.
    const value = writes[path.split("?")[0]];
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value ?? {});
  };
  return {
    ...actual,
    api: { ...actual.api, get, post: write("POST"), put: write("PUT"), del: write("DELETE") },
  };
});

const { ApiError } = await import("../../lib/api");
const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (_whole, key: string) => String(params?.[key] ?? ""));

const active: FleetAuthority = {
  subject: "CN=Flotestro Fleet CA",
  serial: "4a2f90c1b7de3355aa01",
  fingerprint: "aa11bb22cc33dd44",
  not_before: "2026-01-01T00:00:00Z",
  not_after: "2028-01-01T00:00:00Z",
  state: "active",
  hosts_using: 1805,
};

const prepared: FleetAuthority = {
  subject: "CN=Flotestro Fleet CA",
  serial: "77bc10dd55ee9922ff04",
  fingerprint: "ee55ff66aa77bb88",
  not_before: "2026-10-01T00:00:00Z",
  not_after: "2030-10-01T00:00:00Z",
  state: "pending",
  hosts_using: 0,
  prepared_at: "2026-10-01T00:00:00Z",
  hosts_missing: 12,
  relays_missing: 2,
  ready_to_activate: false,
};

const retired: FleetAuthority = {
  subject: "CN=Flotestro Fleet CA",
  serial: "0099aabbccddeeff1122",
  fingerprint: "1234567890abcdef",
  not_before: "2023-01-01T00:00:00Z",
  not_after: "2026-01-01T00:00:00Z",
  state: "retired",
  hosts_using: 0,
};

function draw(options: { mayRotate?: boolean; onError?: (error: unknown) => void } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(
    <CertificateAuthority
      mayRotate={options.mayRotate ?? true}
      reportError={options.onError ?? (() => {})}
    />,
    { wrapper },
  );
}

afterEach(() => {
  cleanup();
  read.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(writes)) delete writes[key];
});

describe("what the section decides before it draws", () => {
  it("makes a key that tells a repeat from a second change", () => {
    const one = changeKey();
    expect(one).not.toBe("");
    expect(changeKey()).not.toBe(one);
  });

  it("holds a change back until the trail will take its reason", () => {
    expect(reasonReady("")).toBe(false);
    expect(reasonReady("  rotate  ")).toBe(false);
    expect(reasonReady("planned rotation")).toBe(true);
  });

  it("reads a state as the one word and the one colour it is", () => {
    expect(authorityStateLabel(t, "active")).toBe("signing");
    expect(authorityStateLabel(t, "pending")).toBe("prepared");
    expect(authorityStateLabel(t, "retired")).toBe("retired");
    expect(authorityTone("active")).toBe("ok");
    expect(authorityTone("pending")).toBe("warn");
    expect(authorityTone("retired")).toBe("unknown");
  });

  it("says what each row means for the next step", () => {
    expect(authorityNote(t, active)).toBe("signs new certificates");
    expect(authorityNote(t, prepared)).toBe("12 hosts do not know it yet");
    expect(authorityNote(t, { ...prepared, hosts_missing: 0, ready_to_activate: true }))
      .toBe("the whole fleet already knows this CA");
    expect(authorityNote(t, { ...retired, hosts_using: 3 })).toBe("still used by hosts");
    expect(authorityNote(t, retired)).toBe("nothing holds its certificates any more");
  });

  it("phrases every refusal the server can give over the trust set", () => {
    const say = (code: string, message = "the server said so") =>
      refusalText(t, new ApiError(409, code, message));
    expect(say("pki_unavailable")).toBe("This panel does not manage the fleet CA.");
    expect(say("reason_required")).toContain("at least eight characters");
    expect(say("idempotency_key_required")).toContain("no key with this change");
    expect(say("change_already_started")).toContain("already begun under this key");
    expect(say("audit_unavailable")).toContain("nothing was changed");
    expect(say("no_pending_ca")).toBe("No CA is prepared for handover.");
    // These two carry a number the server counted, so its own sentence
    // stays beside ours rather than being thrown away.
    expect(say("hosts_missing_ca", "12 hosts do not have the new CA yet"))
      .toContain("12 hosts do not have the new CA yet");
    expect(say("relays_missing_ca", "2 relays do not have the new CA yet"))
      .toContain("2 relays do not have the new CA yet");
    // The two that must not send an operator to repeat the change.
    expect(say("prepared_not_announced")).toContain("Prepare nothing further.");
    expect(say("activated_not_recorded")).toContain("Do not hand over again.");
    expect(say("prepare_failed", "no key material")).toContain("no key material");
    expect(say("activate_failed", "store is locked")).toContain("store is locked");
    expect(say("ca_in_use", "3 hosts still hold it")).toContain("3 hosts still hold it");
    expect(say("invalid_body")).toContain("could not read");
    // One nobody has written a sentence for is still the server's answer,
    // not a blank.
    expect(say("something_new", "a sentence from the server")).toBe("a sentence from the server");
  });
});

describe("what the rows carry", () => {
  it("names the authority, what hangs on it and what it means", async () => {
    answers["/api/v1/pki"] = { authorities: [active, prepared, retired] };
    draw();

    const row = await screen.findByTestId(`authority-${active.fingerprint}`);
    // The serial: the fact the old panel's "Serial" column carried, with
    // the fingerprint on hover, because two authorities of one subject are
    // told apart by nothing else.
    expect(within(row).getByText(active.serial.slice(0, 14))).toBeInTheDocument();
    expect(within(row).getByTitle(`Serial ${active.serial}, fingerprint ${active.fingerprint}`))
      .toBeInTheDocument();
    // The certificates: how many agent certificates hang on this root.
    expect(within(row).getByText("1805")).toBeInTheDocument();
    // The note: what the state means for the next step.
    expect(within(row).getByText("signs new certificates")).toBeInTheDocument();
    expect(within(row).getByText("signing")).toBeInTheDocument();

    const waiting = screen.getByTestId(`authority-${prepared.fingerprint}`);
    expect(within(waiting).getByText("prepared")).toBeInTheDocument();
    expect(within(waiting).getByText("12 hosts do not know it yet")).toBeInTheDocument();

    // The headings the comparison reported as drawn nowhere.
    expect(screen.getByRole("columnheader", { name: "Serial" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Certificates" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Notes" })).toBeInTheDocument();
  });

  it("counts the trust set by state rather than leaving it to be counted by eye", async () => {
    answers["/api/v1/pki"] = { authorities: [active, prepared, retired] };
    draw();
    // Before the answer arrives nothing is counted, and the band says so
    // rather than drawing a fleet with one authority of each kind.
    const band = await screen.findByTestId("ca-trust-set");
    expect(band).toHaveTextContent("signing: not counted");

    await screen.findByTestId(`authority-${active.fingerprint}`);
    expect(within(band).getByText("signing")).toBeInTheDocument();
    expect(within(band).getByText("prepared")).toBeInTheDocument();
    expect(within(band).getByText("retired")).toBeInTheDocument();
  });

  it("says that no host holds a certificate rather than drawing an empty breakdown", async () => {
    answers["/api/v1/pki"] = { authorities: [retired] };
    draw();
    await screen.findByTestId("ca-none-holding");
    expect(screen.getByTestId("ca-none-holding")).toHaveTextContent(
      "No host holds a certificate of any authority.");
  });
});

describe("the two phases of a rotation", () => {
  it("prepares a CA with the reason and a key, and not before the reason is long enough", async () => {
    answers["/api/v1/pki"] = { authorities: [active] };
    draw();

    const button = await screen.findByTestId("ca-prepare");
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByTestId("ca-reason"), { target: { value: "short" } });
    expect(button).toBeDisabled();

    fireEvent.change(screen.getByTestId("ca-reason"),
      { target: { value: "  planned CA rotation before expiry  " } });
    expect(button).toBeEnabled();
    fireEvent.click(button);

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/pki/prepare");
    const body = sent[0].body as { reason: string; idempotency_key: string };
    expect(body.reason).toBe("planned CA rotation before expiry");
    expect(body.idempotency_key).toBeTruthy();
  });

  it("offers the handover only once the fleet knows the prepared CA", async () => {
    answers["/api/v1/pki"] = { authorities: [active, prepared] };
    draw();

    // Phase two, and no second preparation is offered beside it.
    await waitFor(() => expect(screen.getByTestId("ca-phase")).toHaveTextContent("Phase 2"));
    expect(screen.queryByTestId("ca-prepare")).toBeNull();
    expect(screen.getByTestId("ca-phase")).toHaveTextContent("12 remaining");
    // A relay that lacks the new CA loses the site it terminates, so it is
    // said beside the hosts rather than left out.
    expect(screen.getByTestId("ca-relays-missing")).toHaveTextContent("2 relays");

    fireEvent.change(screen.getByTestId("ca-reason"), { target: { value: "handover window" } });
    expect(screen.getByTestId("ca-activate")).toBeDisabled();
  });

  it("hands signing over with the reason and a key", async () => {
    answers["/api/v1/pki"] = {
      authorities: [active, { ...prepared, hosts_missing: 0, relays_missing: 0, ready_to_activate: true }],
    };
    draw();

    const button = await screen.findByTestId("ca-activate");
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByTestId("ca-reason"), { target: { value: "handover window" } });
    expect(button).toBeEnabled();
    fireEvent.click(button);

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/pki/activate");
    expect(sent[0].body).toMatchObject({ reason: "handover window" });
    expect((sent[0].body as { idempotency_key: string }).idempotency_key).toBeTruthy();
  });
});

describe("taking an authority out of the trust set", () => {
  it("asks first, in a dialog, and sends the reason and a key on the address", async () => {
    answers["/api/v1/pki"] = { authorities: [active, retired] };
    draw();

    fireEvent.click(await screen.findByTestId(`ca-remove-${retired.fingerprint}`));
    // Nothing is sent by opening the question.
    expect(sent).toHaveLength(0);

    const confirm = screen.getByTestId("ca-remove-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("ca-remove-reason"),
      { target: { value: "the last host on the old CA was rebuilt" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("DELETE");
    expect(sent[0].path).toContain(`/api/v1/pki/${retired.fingerprint}?`);
    const query = new URLSearchParams(sent[0].path.split("?")[1]);
    expect(query.get("reason")).toBe("the last host on the old CA was rebuilt");
    expect(query.get("idempotency_key")).toBeTruthy();
  });

  it("offers no removal of an authority hosts still hold, or of the one that signs", async () => {
    answers["/api/v1/pki"] = { authorities: [active, prepared, { ...retired, hosts_using: 3 }] };
    draw();
    await screen.findByTestId(`authority-${active.fingerprint}`);
    expect(screen.queryByTestId(`ca-remove-${active.fingerprint}`)).toBeNull();
    expect(screen.queryByTestId(`ca-remove-${prepared.fingerprint}`)).toBeNull();
    expect(screen.queryByTestId(`ca-remove-${retired.fingerprint}`)).toBeNull();
  });
});

describe("what a reader without the permission is offered", () => {
  it("reads the trust set and is offered no change to it", async () => {
    answers["/api/v1/pki"] = { authorities: [active, retired] };
    draw({ mayRotate: false });

    // The facts are all there.
    await screen.findByTestId(`authority-${active.fingerprint}`);
    expect(screen.getByTestId("ca-trust-set")).toBeInTheDocument();
    // And nothing that would change them.
    expect(screen.queryByTestId("ca-reason")).toBeNull();
    expect(screen.queryByTestId("ca-prepare")).toBeNull();
    expect(screen.queryByTestId("ca-activate")).toBeNull();
    expect(screen.queryByTestId(`ca-remove-${retired.fingerprint}`)).toBeNull();
    expect(screen.getByTestId("ca-may-not-rotate")).toBeInTheDocument();
  });

  it("says so when the panel refuses the read, rather than drawing a fleet that trusts nothing", async () => {
    answers["/api/v1/pki"] = new ApiError(403, "forbidden", "not yours");
    draw();
    await screen.findByTestId("ca-forbidden");
    expect(screen.getByTestId("ca-forbidden")).toHaveTextContent(
      "You do not have permission to view the fleet CA.");
    expect(screen.queryByTestId("ca-authorities")).toBeNull();
  });

  it("says that an installation without the module manages no CA here", async () => {
    answers["/api/v1/pki"] = new ApiError(501, "pki_unavailable", "this panel does not manage the fleet CA");
    draw();
    await screen.findByTestId("ca-unreadable");
    expect(screen.getByTestId("ca-unreadable")).toHaveTextContent(
      "This panel does not manage the fleet CA.");
  });
});

describe("a refused change", () => {
  it("is reported upward rather than drawn inside the section", async () => {
    answers["/api/v1/pki"] = { authorities: [active] };
    writes["/api/v1/pki/prepare"] = new ApiError(409, "prepared_not_announced", "not announced");
    const seen: unknown[] = [];
    draw({ onError: (error) => seen.push(error) });

    fireEvent.change(await screen.findByTestId("ca-reason"),
      { target: { value: "planned CA rotation" } });
    fireEvent.click(screen.getByTestId("ca-prepare"));

    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]).toBeInstanceOf(ApiError);
    expect((seen[0] as InstanceType<typeof ApiError>).code).toBe("prepared_not_announced");
  });

  it("reads as the thing to do next, and a stale sign-in is offered the way back", () => {
    const client = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
    );

    const { rerender } = render(
      <CertificateAuthorityWarning
        error={new ApiError(409, "ca_in_use", "3 hosts still hold it")}
        close={() => {}}
      />,
      { wrapper },
    );
    expect(screen.getByTestId("ca-warning")).toHaveTextContent("3 hosts still hold it");
    expect(screen.queryByTestId("ca-step-up")).toBeNull();

    rerender(
      <CertificateAuthorityWarning
        error={new ApiError(401, "reauthentication_required", "sign in again")}
        close={() => {}}
      />,
    );
    expect(screen.getByTestId("ca-step-up")).toBeInTheDocument();

    rerender(<CertificateAuthorityWarning error={null} close={() => {}} />);
    expect(screen.queryByTestId("ca-warning")).toBeNull();
  });
});
