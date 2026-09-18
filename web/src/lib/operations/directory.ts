import {
  define, DOMAIN_NAME, hostnameValid, required, shaped, text,
  type FormProblem, type OperationEntry,
} from "./fields";

/**
 * The directory.
 *
 * Joining carries no password: the one-time credential is fetched from the
 * directory at the moment the task is sent and injected into the envelope,
 * so no secret lies in the database for the life of the order.
 */

const GROUP = "Directory";

export const directory: OperationEntry[] = [
  define({
    action: "identity.host.enroll",
    title: "Join the host to a domain",
    group: GROUP,
    key: "domain_enroll",
    note: "The credential that joins the host is fetched from the directory as the task goes out; it is in neither the order nor the audit trail.",
    fields: [
      {
        name: "domain", label: "Domain", kind: "text", placeholder: "corp.example.com",
        hint: "The domain the host becomes part of.",
      },
      {
        name: "realm", label: "Realm", kind: "text", placeholder: "CORP.EXAMPLE.COM",
        hint: "The Kerberos realm, usually the domain in capitals.",
      },
      {
        name: "server", label: "Server", kind: "text",
        hint: "A particular directory server to join through; empty lets the host find one itself.",
      },
      {
        name: "hostname", label: "Name to join under", kind: "text",
        hint: "Empty joins under the name the host already has. A host joined under the wrong name is invisible to everything that looks it up.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "domain", "Name the domain to join.")) {
        shaped(problems, form, "domain", DOMAIN_NAME, "A domain name has at least two labels, e.g. corp.example.com.");
      }
      required(problems, form, "realm", "Name the Kerberos realm.");
      const name = text(form, "hostname");
      if (name !== "" && !hostnameValid(name)) {
        problems.push({ field: "hostname", message: "The name is a host name in lower case, e.g. web-01.corp.example.com." });
      }
      return problems;
    },
    target: (form) => text(form, "domain"),
  }),
];
