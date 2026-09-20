import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  emptyForm, operationForm, OPERATION_FORMS, payloadTextOf, readPayloadText,
  type FieldValue, type FormValue, type OperationEntry, type OperationField,
} from "./index";
import { actionConstants, literalBody } from "../actions.test";

/* The registry is data, so it is checked as data: every entry has to read
   back what it wrote, refuse an empty form or produce a payload the server
   would take, and together they have to cover every operation the
   catalogue opens to the fleet. The last test is the todo list: it fails
   with the names of the operations still typed as JSON. */

/**
 * The operations the control plane marks campaign-capable, read out of
 * campaignModes itself. A copy of that list would drift the same way the
 * list it copies moves, and the drift would be silent: an operation opened
 * to the fleet with no form is one an operator can only order as raw JSON.
 */
function campaignActions(): string[] {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
  const go = readFileSync(join(root, "internal/opspec/campaigns.go"), "utf8");
  const opspec = readFileSync(join(root, "internal/opspec/opspec.go"), "utf8");
  const constants = actionConstants(opspec);
  const body = literalBody(go, "var campaignModes = map[ActionType]CampaignMode{");
  const out: string[] = [];
  for (const match of body.matchAll(/^\t(Action[A-Za-z0-9]*):/gm)) {
    const name = constants.get(match[1]);
    if (!name) throw new Error(`campaignModes names ${match[1]}, which declares no ActionType`);
    out.push(name);
  }
  // An empty read would let this test pass having checked nothing.
  if (out.length < 20) throw new Error(`campaignModes read as ${out.length} entries`);
  return out;
}

/** A value of the right kind for a field, canonical enough to read back. */
function sample(field: OperationField): FieldValue {
  switch (field.kind) {
    case "boolean":
      return true;
    case "number":
    case "duration":
      return 7;
    case "select": {
      const chosen = (field.options ?? []).find((option) => option.value !== "");
      return chosen?.value ?? "";
    }
    case "list":
      return "one\ntwo";
    case "packages":
      return "curl\nwget";
    case "pairs":
      return "sample.key = value";
    case "unit":
      return "sample.service";
    case "path":
      return "/etc/sample";
    case "textarea":
      return "sample content";
    default:
      return "sample";
  }
}

function filled(entry: OperationEntry): FormValue {
  const form: FormValue = {};
  for (const field of entry.fields) form[field.name] = sample(field);
  return form;
}

describe("the registry", () => {
  it("names every operation once", () => {
    const seen = new Set<string>();
    const repeated = OPERATION_FORMS.filter((entry) => {
      if (seen.has(entry.action)) return true;
      seen.add(entry.action);
      return false;
    });
    expect(repeated.map((entry) => entry.action)).toEqual([]);
  });

  it("gives every entry a title, a group and a look-up by action", () => {
    for (const entry of OPERATION_FORMS) {
      expect(entry.title, entry.action).not.toBe("");
      expect(entry.group, entry.action).not.toBe("");
      expect(operationForm(entry.action)).toBe(entry);
    }
    expect(operationForm("nothing.like.this")).toBeUndefined();
    expect(operationForm(undefined)).toBeUndefined();
  });

  /* No field offers a value somebody's host really carries. The registry
     draws the campaign forms, where no host is known, so a placeholder is
     an example and nothing else - and an example that reads as a real
     device, a real unit or a real address is the one that gets copied into
     an order that formats a disk. The documentation ranges exist for
     exactly this and are the only addresses allowed here. */
  it("offers no device, unit or address a host really has", () => {
    const offered: string[] = [];
    for (const entry of OPERATION_FORMS) {
      for (const field of entry.fields) {
        const example = field.placeholder;
        if (!example) continue;
        const where = `${entry.action}.${field.name}: ${example}`;
        // A path in /dev is the name this kernel handed out this boot.
        if (example.startsWith("/dev/") && !example.endsWith("…")) offered.push(where);
        if (/\.(service|socket|timer|mount|target)\b/.test(example)) offered.push(where);
        for (const address of example.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g) ?? []) {
          if (!/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(address)) offered.push(where);
        }
        // The unique-local prefixes are somebody's own addressing just as
        // much as the private v4 ranges are; 2001:db8:: is the one to show.
        if (/^f[cd][0-9a-f]{2}:/i.test(example)) offered.push(where);
      }
    }
    expect(offered).toEqual([]);
  });

  it("gives every field a name, a label and a kind of its own", () => {
    for (const entry of OPERATION_FORMS) {
      const names = new Set<string>();
      for (const field of entry.fields) {
        expect(field.name, `${entry.action}.${field.name}`).not.toBe("");
        expect(field.label, `${entry.action}.${field.name}`).not.toBe("");
        expect(names.has(field.name), `${entry.action} repeats the field ${field.name}`).toBe(false);
        names.add(field.name);
        if (field.kind === "select") {
          expect((field.options ?? []).length, `${entry.action}.${field.name}`).toBeGreaterThan(0);
        }
      }
    }
  });
});

/** One case per entry, named after the operation it is about. */
const cases: [string, OperationEntry][] = OPERATION_FORMS.map((entry) => [entry.action, entry]);

describe("every entry reads back what it wrote", () => {
  it.each(cases)(
    "%s round-trips a filled form",
    (_action, entry) => {
      const form = filled(entry);
      const payload = entry.toPayload(form);
      expect(entry.fromPayload(payload)).toEqual(form);
      // The same thing through the text the advanced view shows, because
      // that is the way a payload really travels back into the fields.
      expect(readPayloadText(entry, payloadTextOf(entry, form))).toEqual(form);
    },
  );

  it.each(cases)(
    "%s either refuses an empty form or makes a payload of it",
    (_action, entry) => {
      const form = emptyForm(entry);
      const problems = entry.validate(form);
      if (problems.length > 0) {
        // A refusal says which field is missing, or why the order as a
        // whole does not hold together.
        for (const problem of problems) expect(problem.message).not.toBe("");
        return;
      }
      // Nothing is missing, so the empty form is a complete order: what it
      // produces has to come back as the same form.
      expect(entry.fromPayload(entry.toPayload(form))).toEqual(form);
    },
  );

  it("refuses a payload carrying a field the form cannot show", () => {
    const entry = operationForm("unit.restart");
    expect(entry?.fromPayload({ unit: { unit: "cron.service" } })).toEqual({ unit: "cron.service" });
    expect(entry?.fromPayload({ unit: { unit: "cron.service", mode: "hard" } })).toBeNull();
    expect(entry?.fromPayload({ unit_toggle: { unit: "cron.service" } })).toBeNull();
    expect(entry?.fromPayload({ unit: { unit: "cron.service" }, extra: 1 })).toBeNull();
    expect(entry?.fromPayload({ unit: { unit: 7 } })).toBeNull();
  });

  it("refuses text that is not a payload at all", () => {
    const entry = operationForm("unit.restart");
    if (!entry) throw new Error("unit.restart has no form");
    expect(readPayloadText(entry, "not json")).toBeNull();
    expect(readPayloadText(entry, "[1, 2]")).toBeNull();
    expect(readPayloadText(entry, "null")).toBeNull();
  });
});

describe("what the entries refuse", () => {
  it("wants a unit name systemd would accept", () => {
    const entry = operationForm("unit.restart");
    expect(entry?.validate({ unit: "cron.service" })).toEqual([]);
    expect(entry?.validate({ unit: "" })).toHaveLength(1);
    expect(entry?.validate({ unit: "cron" })).toHaveLength(1);
  });

  it("wants the set a removal was approved for", () => {
    const entry = operationForm("packages.remove");
    if (!entry) throw new Error("packages.remove has no form");
    expect(entry.validate({ packages: "nginx", expected_removals: "" })).toHaveLength(1);
    expect(entry.validate({ packages: "nginx", expected_removals: "nginx\nnginx-common" })).toEqual([]);
    expect(entry.toPayload({ packages: "nginx", expected_removals: "nginx\nnginx-common" })).toEqual({
      package_change: { packages: ["nginx"], expected_removals: ["nginx", "nginx-common"] },
    });
  });

  it("adds keys one by one and names removals by fingerprint", () => {
    const add = operationForm("localuser.sshkeys.add");
    if (!add) throw new Error("localuser.sshkeys.add has no form");
    const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI jane@laptop";
    expect(add.toPayload({ name: "jane", public_keys: key, managed_file: false })).toEqual({
      local_user: { name: "jane", keys: [{ public_key: key }] },
    });
    expect(add.validate({ name: "jane", public_keys: "" })).toHaveLength(1);
    expect(add.validate({ name: "jane", public_keys: "-----BEGIN OPENSSH PRIVATE KEY-----" })).toHaveLength(1);

    const remove = operationForm("localuser.sshkeys.remove");
    if (!remove) throw new Error("localuser.sshkeys.remove has no form");
    const fingerprint = `SHA256:${"a".repeat(43)}`;
    expect(remove.validate({ name: "jane", fingerprints: fingerprint })).toEqual([]);
    expect(remove.validate({ name: "jane", fingerprints: "aa:bb:cc" })).toHaveLength(1);
  });

  it("binds a replacement to the keys the operator saw", () => {
    const entry = operationForm("localuser.sshkeys.replace_all");
    if (!entry) throw new Error("localuser.sshkeys.replace_all has no form");
    // The list of what the account has now travels even when it is empty:
    // an empty list is a picture of the account, not missing data.
    expect(entry.toPayload({ name: "jane", ssh_keys: "", expected_fingerprints: "", allow_lockout: true })).toEqual({
      local_user: { name: "jane", allow_lockout: true, ssh_keys: [], expected_fingerprints: [] },
    });
    expect(entry.validate({ name: "jane", ssh_keys: "", expected_fingerprints: "" })).toHaveLength(1);
  });

  it("sends an empty route list rather than leaving it out", () => {
    const entry = operationForm("network.route.ensure");
    expect(entry?.toPayload({ interface: "eth0", routes: "", rollback_seconds: 0 })).toEqual({
      network: { interface: "eth0", routes: [] },
    });
  });

  it("keeps kernel settings inside the branches the panel writes in", () => {
    const entry = operationForm("sysctl.ensure");
    if (!entry) throw new Error("sysctl.ensure has no form");
    expect(entry.validate({ settings: "net.ipv4.ip_forward = 1" })).toEqual([]);
    expect(entry.toPayload({ settings: "net.ipv4.ip_forward = 1" })).toEqual({
      kernel: { settings: { "net.ipv4.ip_forward": "1" } },
    });
    expect(entry.validate({ settings: "dev.something = 1" })).toHaveLength(1);
    expect(entry.validate({ settings: "net.ipv4.ip_forward" })).toHaveLength(1);
    expect(entry.validate({ settings: "" })).toHaveLength(1);
  });

  it("refuses a firewall rule that matches everything", () => {
    const entry = operationForm("firewall.rule.ensure");
    if (!entry) throw new Error("firewall.rule.ensure has no form");
    const rule = { rule_id: "allow-metrics", chain: "input", action: "accept", protocol: "tcp", ports: "9100" };
    expect(entry.validate(rule)).toEqual([]);
    expect(entry.validate({ ...rule, protocol: "", ports: "" })).toHaveLength(1);
    expect(entry.validate({ ...rule, ports: "70000" })).toHaveLength(1);
    expect(entry.validate({ ...rule, sources: "10.0.0.1" })).toHaveLength(1);
  });

  it("only grows a logical volume", () => {
    const entry = operationForm("lvm.extend");
    if (!entry) throw new Error("lvm.extend has no form");
    expect(entry.validate({ device: "/dev/vg0/data", size: "+10G" })).toEqual([]);
    expect(entry.validate({ device: "/dev/vg0/data", size: "10G" })).toHaveLength(1);
    expect(entry.validate({ device: "vg0/data", size: "+10G" })).toHaveLength(1);
  });

  it("does not offer to switch SELinux off", () => {
    const entry = operationForm("selinux.mode.set");
    const values = (entry?.fields[0].options ?? []).map((option) => option.value);
    expect(values).toEqual(["enforcing", "permissive"]);
  });

  it("says where a plan comes first", () => {
    for (const action of ["packages.install", "file.ensure", "mount.ensure", "docker.compose.deploy"]) {
      expect(operationForm(action)?.plan, action).toBeTruthy();
    }
  });

  it("names what a payload acts on", () => {
    expect(operationForm("unit.restart")?.summary({ unit: { unit: "cron.service" } })).toBe("cron.service");
    expect(operationForm("file.ensure")?.summary({ file: { path: "/etc/hosts" } })).toBe("/etc/hosts");
    expect(operationForm("unit.restart")?.summary({ nonsense: true })).toBe("");
  });
});

describe("the operations still typed as JSON", () => {
  it("covers every operation the catalogue opens to the fleet", () => {
    const missing = campaignActions().filter((action) => !operationForm(action));
    expect(missing, `no form yet for: ${missing.join(", ")}`).toEqual([]);
  });
});
