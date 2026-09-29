import { describe, expect, it } from "vitest";
import { renewOrder } from "./Certificates";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* A renewal is ordered from a row, out of values the host itself reported.
   That is a reason to check them, not to trust them: the registry refuses
   here what it refuses in the Bulk workspace, and the row says why instead
   of sending an order the host will turn down. */

function bulk(form: FormValue): Record<string, unknown> {
  const entry = operationForm("certificate.renew");
  if (!entry) throw new Error("the registry has no form for certificate.renew");
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

const tracked = {
  request: "20260101120000",
  path: "/etc/pki/tls/certs/web.crt",
  reload_unit: "httpd.service",
  probe_target: "localhost:443",
};

describe("renewOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    const order = renewOrder(tracked.request, tracked.path, tracked.reload_unit, tracked.probe_target);
    expect(order.payload).toEqual(bulk(tracked));
    expect(order.payload).toEqual({ certificate: tracked });
    expect(order.problems).toEqual([]);
  });

  it("leaves out what the row does not carry", () => {
    expect(renewOrder(tracked.request, tracked.path, "", "").payload)
      .toEqual({ certificate: { request: tracked.request, path: tracked.path } });
  });

  it("refuses what the Bulk workspace refuses", () => {
    const entry = operationForm("certificate.renew");
    for (const change of [
      { request: "not a request id!" },
      { request: "", path: "relative/path.crt" },
      { reload_unit: "httpd.service; rm -rf /" },
      { probe_target: "localhost" },
    ]) {
      const form = { ...tracked, ...change };
      const order = renewOrder(
        String(form.request), String(form.path), String(form.reload_unit), String(form.probe_target),
      );
      expect(order.problems, JSON.stringify(change)).not.toEqual([]);
      expect(order.problems).toEqual(entry?.validate({ ...emptyForm(entry), ...form }));
    }
  });
});
