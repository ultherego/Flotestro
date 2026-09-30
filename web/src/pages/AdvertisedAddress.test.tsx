import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import {
  AdvertisedAddressSection, OWN_ADDRESS, candidateNote, chosenAddress, confirmable, sourceTone,
  type AdvertisedAddress,
} from "./AdvertisedAddress";

let answers: Record<string, unknown>;
const written: { path: string; body: unknown }[] = [];

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) =>
        path in answers ? Promise.resolve(answers[path]) : Promise.reject(new Error(`no answer for ${path}`)),
      put: (path: string, body: unknown) => {
        written.push({ path, body });
        return Promise.resolve(answers["put:" + path] ?? answers[path]);
      },
      post: () => Promise.reject(new Error("the test writes nothing this way")),
      del: () => Promise.reject(new Error("the test deletes nothing")),
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  written.length = 0;
});

const loopbackOnly: AdvertisedAddress = {
  in_force: ["127.0.0.1"],
  source: "default",
  loopback_only: true,
  environment_in_force: false,
  candidates: [
    { name: "192.168.56.10", kind: "address", interface: "eth1", loopback: false },
    { name: "panel.example.test", kind: "hostname", loopback: false },
    { name: "127.0.0.1", kind: "address", interface: "lo", loopback: true },
  ],
  note: "A confirmed address takes effect on every replica within half a minute.",
};

describe("what the administrator is about to confirm", () => {
  it("is nothing until a choice is made, so the first proposal is never sent", () => {
    expect(chosenAddress("", "")).toEqual([]);
    expect(confirmable(chosenAddress("", ""), false)).toBe(false);
  });

  it("is the candidate that was picked, or what was typed instead", () => {
    expect(chosenAddress("192.168.56.10", "typed.example.test")).toEqual(["192.168.56.10"]);
    expect(chosenAddress(OWN_ADDRESS, " panel.example.test ")).toEqual(["panel.example.test"]);
    expect(chosenAddress(OWN_ADDRESS, "a.example.test, b.example.test"))
      .toEqual(["a.example.test", "b.example.test"]);
    expect(chosenAddress(OWN_ADDRESS, "  ")).toEqual([]);
  });

  it("is refused here as well as on the server, so nothing is sent to be refused", () => {
    expect(confirmable(["panel.example.test"], false)).toBe(true);
    expect(confirmable(["https://panel.example.test"], false)).toBe(false);
    expect(confirmable(["panel.example.test"], true)).toBe(false);
  });
});

describe("the state of the address", () => {
  it("reads as a fault while the panel reaches only its own machine", () => {
    expect(sourceTone("default", true)).toBe("error");
    expect(sourceTone("default", false)).toBe("warn");
    expect(sourceTone("confirmed", false)).toBe("ok");
    expect(sourceTone("environment", false)).toBe("ok");
  });

  it("says where a candidate was found without inventing anything", () => {
    const t = (s: string, v?: Record<string, string | number>) =>
      s.replace(/\{(\w+)\}/g, (_, key) => String(v?.[key] ?? ""));
    expect(candidateNote({ name: "192.168.56.10", kind: "address", interface: "eth1", loopback: false }, t))
      .toBe("on the interface eth1");
    expect(candidateNote({ name: "127.0.0.1", kind: "address", interface: "lo", loopback: true }, t))
      .toBe("on the interface lo, reaches only this machine");
    expect(candidateNote({ name: "panel", kind: "hostname", loopback: false }, t))
      .toBe("the name this machine answers to");
  });
});

describe("the section", () => {
  it("offers the detected addresses as proposals and confirms none by itself", async () => {
    answers = { "/api/v1/settings/advertised": loopbackOnly };
    draw(<AdvertisedAddressSection mayConfirm />);
    await waitFor(() => expect(screen.getByText("192.168.56.10")).toBeInTheDocument());

    // Visibly a proposal, and nothing has been sent.
    expect(screen.getByText("proposal")).toBeInTheDocument();
    expect(written).toHaveLength(0);
    // The address in force is still the loopback one the panel started with.
    expect(screen.getByTestId("advertised-address")).toHaveTextContent("In force: 127.0.0.1");
    expect(screen.getByText("not confirmed")).toBeInTheDocument();
    // And the button cannot be pressed while nothing is chosen.
    expect(screen.getByRole("button", { name: /Confirm the address/ })).toBeDisabled();
  });

  it("sends the chosen name only once it has been chosen", async () => {
    answers = {
      "/api/v1/settings/advertised": loopbackOnly,
      "put:/api/v1/settings/advertised": {
        ...loopbackOnly, in_force: ["192.168.56.10"], source: "confirmed",
        loopback_only: false, confirmed: ["192.168.56.10"], confirmed_by: "admin",
      },
      "/api/v1/installation-profiles?kind=agent": {
        config: { path: "/etc/flotestro/agent.yaml", content: "connection:\n  enrollment_url: \"https://192.168.56.10:8444\"\n" },
        warnings: [],
      },
    };
    draw(<AdvertisedAddressSection mayConfirm />);
    await waitFor(() => expect(screen.getByText("192.168.56.10")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("radio", { name: /192\.168\.56\.10/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Confirm 192\.168\.56\.10/ }));

    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0]).toEqual({
      path: "/api/v1/settings/advertised",
      body: { names: ["192.168.56.10"], reason: "" },
    });
    // After the confirmation the screen shows what a new host is now told.
    await waitFor(() =>
      expect(screen.getByTestId("advertised-agent-config")).toHaveTextContent("192.168.56.10:8444"));
  });

  it("offers no choice where the deployment declares the address", async () => {
    answers = {
      "/api/v1/settings/advertised": {
        ...loopbackOnly,
        in_force: ["declared.example.test"], source: "environment", loopback_only: false,
        environment: ["declared.example.test"], environment_in_force: true,
        confirmed: ["confirmed.example.test"],
        mismatch: "the environment of the control plane advertises declared.example.test and an " +
          "administrator confirmed confirmed.example.test; the environment decides",
      } satisfies AdvertisedAddress,
    };
    draw(<AdvertisedAddressSection mayConfirm />);
    await waitFor(() => expect(screen.getByText("declared.example.test")).toBeInTheDocument());
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    // The disagreement is shown rather than resolved in silence.
    expect(screen.getByText(/the environment decides/)).toBeInTheDocument();
  });

  it("says who may confirm when the reader may not", async () => {
    answers = { "/api/v1/settings/advertised": loopbackOnly };
    draw(<AdvertisedAddressSection mayConfirm={false} />);
    await waitFor(() =>
      expect(screen.getByText(/Only a platform administrator/)).toBeInTheDocument());
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });
});
