import {
  ACCOUNT_NAME, define, each, EXPIRY_DATE, FINGERPRINT, flag, formOf, list, payloadOf,
  publicKeyValid, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Local accounts and their keys.
 *
 * The panel sets no passwords: an account it creates is reachable by SSH
 * key alone, so there is no secret it would have to keep or carry. That is
 * why a key list is not decoration here - it is the whole way in, and an
 * order that empties it is an order that cuts somebody off.
 */

const GROUP = "Accounts";

const nameField: OperationField = {
  name: "name",
  label: "Account",
  kind: "text",
  hint: "The login name on the host, as the host's accounts page lists it. The account is not created by these operations unless they say so.",
};

const managedFileField: OperationField = {
  name: "managed_file",
  label: "Keep the keys in the panel's own file",
  kind: "boolean",
  hint: "Writes to the panel's file under /etc/ssh/authorized_keys.d instead of the account's own authorized_keys, so a key somebody added by hand is left alone. A host whose sshd does not read that file refuses the order.",
};

const allowLockoutField: OperationField = {
  name: "allow_lockout",
  label: "Allow this to leave the account with no way in",
  kind: "boolean",
  hint: "Without it an order that would take the last key of an account nobody can log into otherwise is refused.",
};

/** The account name is required and has to be one the host would accept. */
function nameCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "name", "Name the account this acts on.")) {
    shaped(problems, form, "name", ACCOUNT_NAME,
      "An account name starts with a lower-case letter or an underscore and is at most 32 characters.");
  }
  return problems;
}

/** Every line of a key field has to be a public key the panel would place. */
function keysCheck(problems: FormProblem[], keys: string[], field: string): void {
  if (keys.length > 64) {
    problems.push({ field, message: "One order carries at most 64 keys." });
    return;
  }
  const offending = keys.find((key) => !publicKeyValid(key));
  if (offending !== undefined) {
    problems.push({
      field,
      message: offending.includes("PRIVATE KEY")
        ? "That is a private key. The panel places public keys, and a private key must never leave the machine it was made on."
        : "A key is one line: the type, the material and an optional comment.",
    });
  }
}

function fingerprintsCheck(problems: FormProblem[], fingerprints: string[], field: string): void {
  each(problems, fingerprints, field, FINGERPRINT,
    "{value} is not a fingerprint; the host names keys as SHA256:<digest>.");
}

/** The fields an add carries next to the keys themselves. */
const addBase: OperationField[] = [nameField, managedFileField];

/** The fields a replace carries next to the key list and the fingerprints. */
const replaceBase: OperationField[] = [nameField, managedFileField, allowLockoutField];

export const accounts: OperationEntry[] = [
  define({
    action: "localuser.create",
    title: "Create a local account",
    group: GROUP,
    key: "local_user",
    note: "The panel sets no password: the account is reachable by the keys given here, or by nothing at all if it is created inactive.",
    fields: [
      nameField,
      { name: "gecos", label: "Description", kind: "text", hint: "The person or the purpose behind the account; it lands in the account's description field." },
      { name: "shell", label: "Shell", kind: "text", placeholder: "/bin/bash", hint: "An absolute path; empty leaves the host's default." },
      { name: "groups", label: "Groups", kind: "list", hint: "One per line. A group that grants administrative rights is treated as a privileged change." },
      {
        name: "ssh_keys", label: "Keys the account may log in with", kind: "list", wide: true,
        hint: "One public key per line. This is the only way in the panel can give the account.",
      },
      { name: "create_home", label: "Create a home directory", kind: "boolean" },
      {
        name: "system", label: "It is a system account", kind: "boolean",
        hint: "The account is allocated below the range of people who log in. Without this a system account is refused on the host.",
      },
      {
        name: "inactive", label: "Create it with no way in", kind: "boolean",
        hint: "For an account a service runs under and nobody logs into. It takes no keys, and without this an account with no key at all is refused.",
      },
      managedFileField,
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const groups = list(form, "groups");
      if (groups.length > 64) {
        problems.push({ field: "groups", message: "One order carries at most 64 groups." });
      }
      each(problems, groups, "groups", ACCOUNT_NAME, "{value} is not a group name.");
      const shell = text(form, "shell");
      if (shell !== "" && !shell.startsWith("/")) {
        problems.push({ field: "shell", message: "The shell is named by its absolute path." });
      }
      if (/[:\n]/.test(text(form, "gecos"))) {
        problems.push({ field: "gecos", message: "The description carries no colon and no newline." });
      }
      const keys = list(form, "ssh_keys");
      keysCheck(problems, keys, "ssh_keys");
      if (keys.length === 0 && !flag(form, "inactive")) {
        problems.push({
          field: "ssh_keys",
          message: "The account would have no key and no password, so nobody could log in. Give it a key, or say it is to be created with no way in.",
        });
      }
      if (keys.length > 0 && flag(form, "inactive")) {
        problems.push({ field: "inactive", message: "An account created with no way in takes no keys." });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.lock",
    title: "Lock a local account",
    group: GROUP,
    key: "local_user",
    note: "The account stays on the host with everything it owns; it simply cannot log in until it is unlocked.",
    fields: [nameField],
    check: nameCheck,
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.unlock",
    title: "Unlock a local account",
    group: GROUP,
    key: "local_user",
    fields: [nameField],
    check: nameCheck,
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.delete",
    title: "Delete a local account",
    group: GROUP,
    key: "local_user",
    fields: [
      nameField,
      {
        name: "remove_home", label: "Delete the home directory too", kind: "boolean",
        hint: "Off leaves the files where they are, owned by a number nobody answers to any more.",
      },
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const name = text(form, "name");
      if (["root", "nobody", "flotestro", "flotestro-agent", "flotestro-relay"].includes(name)) {
        problems.push({
          field: "name",
          message: "The account {value} is not deleted through the panel.",
          params: { value: name },
        });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.groups.set",
    title: "Set which groups an account is in",
    group: GROUP,
    key: "local_user",
    note: "The list is the whole membership, not an addition: a group missing from it is a group the account leaves.",
    fields: [
      nameField,
      { name: "groups", label: "Groups", kind: "list", wide: true, hint: "One per line; an empty list leaves the account in its own group alone." },
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const groups = list(form, "groups");
      if (groups.length > 64) {
        problems.push({ field: "groups", message: "One order carries at most 64 groups." });
      }
      each(problems, groups, "groups", ACCOUNT_NAME, "{value} is not a group name.");
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.expiry.set",
    title: "Set when an account stops working",
    group: GROUP,
    key: "local_user",
    fields: [
      nameField,
      {
        name: "expires_at", label: "Expires on", kind: "text", placeholder: "2026-12-31",
        hint: "A date as YYYY-MM-DD. A date in the past cuts access off now, with a record of when. Empty takes the expiry away.",
      },
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const value = text(form, "expires_at");
      if (value !== "" && (!EXPIRY_DATE.test(value) || Number.isNaN(Date.parse(value)))) {
        problems.push({ field: "expires_at", message: "The date is written as YYYY-MM-DD." });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.sshkeys.add",
    title: "Add SSH keys to an account",
    group: GROUP,
    key: "local_user",
    note: "Only the keys named here are added; everything the account already has stays. Ordering the same key twice adds it once.",
    fields: [
      ...addBase,
      {
        name: "public_keys", label: "Keys to add", kind: "list", wide: true,
        hint: "One public key per line, options included if the key carries any.",
      },
    ],
    extra: ["keys"],
    compose: (form) => {
      const keys = list(form, "public_keys");
      return {
        ...payloadOf(addBase, form),
        ...(keys.length > 0 ? { keys: keys.map((key) => ({ public_key: key })) } : {}),
      };
    },
    read: (section) => {
      const base = formOf(addBase, section);
      if (!base) return null;
      const raw = section.keys;
      if (raw === undefined || raw === null) return { ...base, public_keys: "" };
      if (!Array.isArray(raw)) return null;
      const lines: string[] = [];
      for (const item of raw) {
        if (!item || typeof item !== "object" || Array.isArray(item)) return null;
        const record = item as Record<string, unknown>;
        if (Object.keys(record).some((name) => name !== "public_key" && name !== "comment")) return null;
        if (typeof record.public_key !== "string") return null;
        // A comment of its own belongs to the key's line; a form that showed
        // the line alone would drop it on the next keystroke.
        if (record.comment !== undefined && record.comment !== "") return null;
        lines.push(record.public_key);
      }
      return { ...base, public_keys: lines.join("\n") };
    },
    check: (form) => {
      const problems = nameCheck(form);
      const keys = list(form, "public_keys");
      if (keys.length === 0) {
        problems.push({ field: "public_keys", message: "Name at least one key to add." });
      }
      keysCheck(problems, keys, "public_keys");
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.sshkeys.remove",
    title: "Take SSH keys away from an account",
    group: GROUP,
    key: "local_user",
    note: "Keys are named by fingerprint, because that is what the host reports about them; everything not named here stays.",
    fields: [
      nameField,
      {
        name: "fingerprints", label: "Fingerprints to take away", kind: "list", wide: true,
        placeholder: "SHA256:…",
        hint: "One per line, as the account's key list shows them.",
      },
      {
        name: "ignore_missing", label: "Do not fail on a key that is already gone", kind: "boolean",
        hint: "Without it a fingerprint the account does not have refuses the order, so a stale list does not pass as done.",
      },
      allowLockoutField,
      managedFileField,
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const fingerprints = list(form, "fingerprints");
      if (fingerprints.length === 0) {
        problems.push({ field: "fingerprints", message: "Name at least one key to take away." });
      }
      if (fingerprints.length > 64) {
        problems.push({ field: "fingerprints", message: "One order carries at most 64 fingerprints." });
      }
      fingerprintsCheck(problems, fingerprints, "fingerprints");
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.sshkeys.replace_all",
    title: "Replace every SSH key of an account",
    group: GROUP,
    key: "local_user",
    note: "The list below becomes the whole set of keys; an empty one takes access away. The fingerprints say what the account has now, and a key added or removed in the meantime makes the order stale and it is refused.",
    fields: [
      ...replaceBase,
      { name: "ssh_keys", label: "The keys the account is to have", kind: "list", wide: true, hint: "One public key per line." },
      {
        name: "expected_fingerprints", label: "The keys it has now", kind: "list", wide: true,
        placeholder: "SHA256:…",
        hint: "One fingerprint per line, exactly what the account's key list shows. Leave it empty only when the account really has no key.",
      },
    ],
    compose: (form) => ({
      ...payloadOf(replaceBase, form),
      ssh_keys: list(form, "ssh_keys"),
      expected_fingerprints: list(form, "expected_fingerprints"),
    }),
    check: (form) => {
      const problems = nameCheck(form);
      const keys = list(form, "ssh_keys");
      keysCheck(problems, keys, "ssh_keys");
      const fingerprints = list(form, "expected_fingerprints");
      if (fingerprints.length > 256) {
        problems.push({ field: "expected_fingerprints", message: "An account with more than 256 keys is not replaced in one order." });
      }
      fingerprintsCheck(problems, fingerprints, "expected_fingerprints");
      if (keys.length === 0 && !flag(form, "allow_lockout")) {
        problems.push({
          field: "ssh_keys",
          message: "An empty list takes every way in away from the account. Say so explicitly, or name the keys it keeps.",
        });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "localuser.sshkeys.set",
    title: "Set the SSH keys of an account (older operation)",
    group: GROUP,
    key: "local_user",
    note: "This is the earlier form of the replacement and runs without knowing what the account had. Prefer replacing every key, which is bound to the list the operator saw; this one stays for hosts running an older agent.",
    fields: [
      ...replaceBase,
      { name: "ssh_keys", label: "The keys the account is to have", kind: "list", wide: true, hint: "One public key per line; the list replaces everything the account has." },
      {
        name: "expected_fingerprints", label: "The keys it has now", kind: "list", wide: true,
        hint: "Optional here, and the reason to prefer the newer operation: without it the replacement runs blind.",
      },
    ],
    check: (form) => {
      const problems = nameCheck(form);
      const keys = list(form, "ssh_keys");
      keysCheck(problems, keys, "ssh_keys");
      fingerprintsCheck(problems, list(form, "expected_fingerprints"), "expected_fingerprints");
      if (keys.length === 0 && !flag(form, "allow_lockout")) {
        problems.push({
          field: "ssh_keys",
          message: "An empty list takes every way in away from the account. Say so explicitly, or name the keys it keeps.",
        });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),
];
