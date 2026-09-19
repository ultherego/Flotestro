import {
  absolute, ANCHOR_NAME, define, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Certificates and the authorities behind them.
 */

const GROUP = "Certificates";

const PLAN_NOTE =
  "Every host computes its own plan first: the planning step shows the fingerprint it serves now against the one ordered, when it expires, which service has to reread the file and what will be probed afterwards.";

const reloadField: OperationField = {
  name: "reload_unit",
  label: "Service that has to reread it",
  kind: "text",
  hint: "The unit that serves the certificate, as the host's services page names it. Without it the change ends as a new file on disk and the old identity still in the running process - a change nobody can see.",
};

const probeField: OperationField = {
  name: "probe_target",
  label: "Check it at",
  kind: "text",
  placeholder: "localhost:443",
  hint: "Where the host asks whether the service really serves the certificate just written. It compares fingerprints, not trust.",
};

function serviceCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (/[\s/;&|$`]/.test(text(form, "reload_unit"))) {
    problems.push({ field: "reload_unit", message: "A unit name carries no space, slash or shell character." });
  }
  const probe = text(form, "probe_target");
  if (probe !== "") {
    const index = probe.lastIndexOf(":");
    const port = Number(probe.slice(index + 1));
    if (index <= 0 || !Number.isInteger(port) || port < 1 || port > 65535) {
      problems.push({ field: "probe_target", message: "The probe target has the form host:port." });
    }
  }
  return problems;
}

export const certificates: OperationEntry[] = [
  define({
    action: "certificate.deploy",
    title: "Put a certificate on the host",
    group: GROUP,
    key: "certificate",
    plan: PLAN_NOTE,
    note: "The private key is not typed here: it is fetched from the secret store at the moment of the swap. An order that carries one is edited in the advanced view.",
    fields: [
      {
        name: "path", label: "Certificate file", kind: "path", wide: true,
        hint: "Where the service reads its certificate from, copied from that service's own configuration; the file is replaced in place.",
      },
      { name: "key_path", label: "Key file", kind: "path", hint: "Where the private key is to land; needed when the key comes from the store." },
      {
        name: "certificate", label: "Certificate and its chain", kind: "textarea", wide: true,
        hint: "In PEM, the host's own certificate first and the issuers after it. The panel checks the chain here so a broken one is refused before the approval.",
      },
      { name: "owner", label: "Owner", kind: "text" },
      { name: "group", label: "Group", kind: "text" },
      { name: "mode", label: "Certificate permissions", kind: "text", placeholder: "0644" },
      { name: "key_mode", label: "Key permissions", kind: "text", placeholder: "0600" },
      reloadField,
      probeField,
    ],
    check: (form) => {
      const problems = serviceCheck(form);
      if (required(problems, form, "path", "Say where the certificate is to land.")) {
        absolute(problems, form, "path", "The path is absolute and does not walk out of its directory.");
      }
      absolute(problems, form, "key_path", "The path is absolute and does not walk out of its directory.");
      const material = text(form, "certificate");
      if (material === "") {
        problems.push({ field: "certificate", message: "Paste the certificate; a deployment without one has nothing to put in place." });
      } else if (!material.includes("-----BEGIN CERTIFICATE-----")) {
        problems.push({ field: "certificate", message: "That is not a certificate in PEM form." });
      } else if (material.includes("PRIVATE KEY")) {
        problems.push({
          field: "certificate",
          message: "A private key was pasted in with the certificate. The key comes from the secret store and never travels in the order.",
        });
      }
      for (const field of ["mode", "key_mode"]) {
        const value = text(form, field);
        if (value !== "" && !/^0?[0-7]{3,4}$/.test(value)) {
          problems.push({ field, message: "Permissions are three or four octal digits, e.g. 0644." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "path"),
  }),

  define({
    action: "certificate.renew",
    title: "Have the host renew a certificate",
    group: GROUP,
    key: "certificate",
    plan: "Every host computes its own plan first: the planning step says whether the host has anyone to order the renewal from and what watches that file now.",
    note: "There is no material here: the host's own daemon goes to its authority for the new certificate.",
    fields: [
      {
        name: "request", label: "Request", kind: "text",
        hint: "The certmonger request identifier. It is different on every host, so a campaign across the fleet names the file instead.",
      },
      {
        name: "path", label: "Certificate file", kind: "path", wide: true,
        hint: "The file the renewal is about. This is what a campaign names: the same path means the same certificate everywhere.",
      },
      reloadField,
      probeField,
    ],
    check: (form) => {
      const problems = serviceCheck(form);
      const request = text(form, "request");
      if (request === "") {
        if (!required(problems, form, "path", "Name the request, or the file the renewal is about.")) return problems;
        absolute(problems, form, "path", "The path is absolute and does not walk out of its directory.");
      } else if (!/^[A-Za-z0-9._-]{1,128}$/.test(request)) {
        problems.push({ field: "request", message: "A request identifier is letters, digits and . _ - ." });
      }
      return problems;
    },
    target: (form) => text(form, "path") || text(form, "request"),
  }),

  define({
    action: "certificate.trust.ensure",
    title: "Have the host trust an authority",
    group: GROUP,
    key: "certificate",
    plan: "Every host computes its own plan first: the planning step says whether the host already trusts this authority.",
    fields: [
      {
        name: "anchor_id", label: "Authority", kind: "text", placeholder: "corporate-root",
        hint: "How the panel recognises its own anchor in the host's trust store; the file on the host is named after it.",
      },
      {
        name: "certificate", label: "The authority's certificate", kind: "textarea", wide: true,
        hint: "In PEM. Everything this authority signs becomes trusted on the host, so this is material to read before approving.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "anchor_id", "Give the authority a name in the panel.")) {
        shaped(problems, form, "anchor_id", ANCHOR_NAME,
          "The name is lower-case letters, digits and . _ - .");
      }
      const material = text(form, "certificate");
      if (material === "") {
        problems.push({ field: "certificate", message: "Paste the authority's certificate." });
      } else if (!material.includes("-----BEGIN CERTIFICATE-----")) {
        problems.push({ field: "certificate", message: "That is not a certificate in PEM form." });
      }
      return problems;
    },
    target: (form) => text(form, "anchor_id"),
  }),

  define({
    action: "certificate.trust.remove",
    title: "Have the host stop trusting an authority",
    group: GROUP,
    key: "certificate",
    plan: "Every host computes its own plan first: the planning step says whether that authority still signs anything the host shows to its clients.",
    note: "Withdrawing an authority applies to the whole fleet at once: as long as even one host has not confirmed the new trust, the old one stays.",
    fields: [
      { name: "anchor_id", label: "Authority", kind: "text", hint: "The name the panel keeps the anchor under." },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "anchor_id", "Name the authority to withdraw.")) {
        shaped(problems, form, "anchor_id", ANCHOR_NAME, "The name is lower-case letters, digits and . _ - .");
      }
      return problems;
    },
    target: (form) => text(form, "anchor_id"),
  }),
];
