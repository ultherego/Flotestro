import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, PASSWORD_CHANGE_PATH, api } from "./api";

/**
 * A session on a password somebody else chose is confined by the server to the
 * change of it. Every other screen would show a bare 403; the client takes the
 * reader to the form instead, and does not loop once it is there.
 */

function answer(status: number, body: unknown) {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/problem+json" },
  }))));
}

const assign = vi.fn();

function at(pathname: string) {
  vi.stubGlobal("location", { pathname, assign });
}

afterEach(() => {
  vi.unstubAllGlobals();
  assign.mockReset();
});

describe("the password that has to be replaced", () => {
  it("takes the reader to the form for the change, from any other screen", async () => {
    at("/hosts");
    answer(403, { code: "password_change_required", detail: "change it before anything else" });
    await expect(api.get("/api/v1/hosts")).rejects.toBeInstanceOf(ApiError);
    expect(assign).toHaveBeenCalledWith(PASSWORD_CHANGE_PATH);
  });

  it("does not send the reader where they already are", async () => {
    at("/profile");
    answer(403, { code: "password_change_required", detail: "x" });
    await expect(api.get("/api/v1/hosts")).rejects.toBeInstanceOf(ApiError);
    expect(assign).not.toHaveBeenCalled();
  });

  it("leaves every other refusal alone", async () => {
    at("/hosts");
    answer(403, { code: "forbidden", detail: "not yours" });
    await expect(api.get("/api/v1/hosts")).rejects.toBeInstanceOf(ApiError);
    expect(assign).not.toHaveBeenCalled();
  });
});
