import {
  absolute, define, required, SHA256, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Configuration files.
 *
 * A write is never blind: the planning step reads what the host has now and
 * returns the digest of it, and the write comes back carrying that digest.
 * A file somebody else changed in the meantime stops the change instead of
 * overwriting their work, which is why the digest is not a field here.
 */

const GROUP = "Files";

const PLAN_NOTE =
  "Every host computes its own difference first: the planning step shows what the file holds now and what would change, and the write is bound to the content the host had at that moment.";

const pathField: OperationField = {
  name: "path",
  label: "File",
  kind: "path",
  hint: "The absolute path on the host, e.g. /etc/chrony/chrony.conf.",
  placeholder: "/etc/…",
  wide: true,
};

function pathCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "path", "Name the file this acts on.")) {
    absolute(problems, form, "path",
      "The path is absolute, does not walk up out of its directory and carries no wildcard.");
  }
  return problems;
}

export const files: OperationEntry[] = [
  define({
    action: "file.ensure",
    title: "Write a configuration file",
    group: GROUP,
    key: "file",
    plan: PLAN_NOTE,
    fields: [
      pathField,
      {
        name: "content",
        label: "Content",
        kind: "textarea",
        hint: "What the file is to hold, in full. The panel writes files whole, so what stands here is what the host will have.",
        wide: true,
      },
      { name: "owner", label: "Owner", kind: "text", hint: "Leave empty to keep the owner the file has." },
      { name: "group", label: "Group", kind: "text", hint: "Leave empty to keep the group the file has." },
      {
        name: "mode", label: "Permissions", kind: "text", placeholder: "0644",
        hint: "In octal, as chmod takes it. Empty keeps the permissions the file has.",
      },
      {
        name: "validator",
        label: "Check it with",
        kind: "text",
        hint: "The host's own checker for this kind of file, e.g. sshd or nginx. A file it refuses is not written.",
      },
      {
        name: "allow_missing_validator",
        label: "Write it even where the checker is missing",
        kind: "boolean",
        hint: "Without this a host without the checker refuses the write. Saying so here is not enough on its own: the account also needs the right to write unchecked files.",
      },
    ],
    check: (form) => {
      const problems = pathCheck(form);
      if (text(form, "mode") !== "" && !/^0?[0-7]{3,4}$/.test(text(form, "mode"))) {
        problems.push({ field: "mode", message: "Permissions are three or four octal digits, e.g. 0644." });
      }
      return problems;
    },
    target: (form) => text(form, "path"),
  }),

  define({
    action: "file.remove",
    title: "Remove a configuration file",
    group: GROUP,
    key: "file",
    plan: PLAN_NOTE,
    fields: [pathField],
    check: pathCheck,
    target: (form) => text(form, "path"),
  }),

  define({
    action: "file.rollback",
    title: "Put a file back to an earlier version",
    group: GROUP,
    key: "file",
    plan: PLAN_NOTE,
    fields: [
      pathField,
      {
        name: "version_sha256",
        label: "Version to come back to",
        kind: "text",
        hint: "The SHA-256 of the version from the file's history. Empty takes the one immediately before the last change the panel made.",
        wide: true,
      },
    ],
    check: (form) => {
      const problems = pathCheck(form);
      shaped(problems, form, "version_sha256", SHA256,
        "A version is named by its SHA-256: sixty-four hexadecimal characters.");
      return problems;
    },
    target: (form) => text(form, "path"),
  }),
];
