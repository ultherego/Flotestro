import {
  count, define, each, flag, list, PACKAGE_NAME, REPOSITORY_ID, required, shaped, text, words,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Packages and the sources they come from.
 *
 * An installation and an upgrade compute a different transaction on every
 * host, so they carry no set of versions here: the planning step reads what
 * each host would really do and the approval covers that set. A source, a
 * hold and a repair are declarations about a name and mean the same
 * everywhere.
 */

const GROUP = "Packages";

const PLAN_NOTE =
  "Every host computes its own transaction first: the planning step shows what each one would install, upgrade or remove, and the approval covers that set rather than this form.";

const packageList: OperationField = {
  name: "packages",
  label: "Packages",
  kind: "packages",
  hint: "One name per line, or separated by commas. The name is the one the host's package manager knows.",
  placeholder: "nginx\ncurl",
  wide: true,
};

function packagesCheck(form: FormValue, field: string, message: string): FormProblem[] {
  const problems: FormProblem[] = [];
  const names = words(form, field);
  if (names.length === 0) {
    problems.push({ field, message });
    return problems;
  }
  if (names.length > 500) {
    problems.push({ field, message: "One order covers at most 500 packages." });
    return problems;
  }
  each(problems, names, field, PACKAGE_NAME, "{value} is not a package name.");
  return problems;
}

export const packages: OperationEntry[] = [
  define({
    action: "packages.install",
    title: "Install packages",
    group: GROUP,
    key: "package_change",
    plan: PLAN_NOTE,
    fields: [packageList],
    check: (form) => packagesCheck(form, "packages", "Name at least one package to install."),
    target: (form) => words(form, "packages").join(", "),
  }),

  define({
    action: "packages.remove",
    title: "Remove packages",
    group: GROUP,
    key: "package_change",
    plan: PLAN_NOTE,
    fields: [
      packageList,
      {
        name: "expected_removals",
        label: "Everything the removal may take with it",
        kind: "packages",
        hint: "The full set the operator reviewed, dependencies included. The host computes the set again right before the removal and refuses when it differs, so nothing disappears that nobody saw.",
        wide: true,
      },
    ],
    check: (form) => {
      const problems = packagesCheck(form, "packages", "Name at least one package to remove.");
      const approved = words(form, "expected_removals");
      if (approved.length === 0) {
        problems.push({
          field: "expected_removals",
          message: "A removal carries the set the operator approved; plan it on one host first and copy the set in.",
        });
      }
      each(problems, approved, "expected_removals", PACKAGE_NAME, "{value} is not a package name.");
      return problems;
    },
    target: (form) => words(form, "packages").join(", "),
  }),

  define({
    action: "packages.upgrade",
    title: "Install the pending updates",
    group: GROUP,
    key: "package_upgrade",
    plan: PLAN_NOTE,
    fields: [
      {
        name: "security_only",
        label: "Security updates only",
        kind: "boolean",
        default: true,
        hint: "On leaves every update the distribution does not mark as a security fix where it is.",
      },
      {
        name: "packages",
        label: "Limit it to these packages",
        kind: "packages",
        hint: "Empty means every pending update the choice above allows.",
        wide: true,
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      each(problems, words(form, "packages"), "packages", PACKAGE_NAME, "{value} is not a package name.");
      return problems;
    },
    target: (form) => words(form, "packages").join(", "),
  }),

  define({
    action: "packages.hold.set",
    title: "Freeze or release a package version",
    group: GROUP,
    key: "package_change",
    fields: [
      packageList,
      {
        name: "hold",
        label: "Freeze the version",
        kind: "boolean",
        hint: "On keeps the version the host has now through every upgrade; off lets the package move again.",
      },
    ],
    check: (form) => packagesCheck(form, "packages", "Name at least one package to freeze or release."),
    target: (form) => words(form, "packages").join(", "),
  }),

  define({
    action: "packages.repository.set",
    title: "Set up or remove a package source",
    group: GROUP,
    key: "repository",
    note: "The host fetches the source's metadata itself and reports the key's fingerprint in the result; only a person can compare it with the one the supplier published.",
    fields: [
      {
        name: "id",
        label: "Identifier",
        kind: "text",
        hint: "How the panel recognises this source on every host; it names the file the host writes.",
        placeholder: "internal-tools",
      },
      { name: "name", label: "Name", kind: "text", hint: "What the source is called in the host's own listing." },
      {
        name: "url",
        label: "Address",
        kind: "text",
        hint: "Where the packages come from, over http or https. A source whose signatures are not checked has to be at least https.",
        placeholder: "https://packages.example.com/debian",
        wide: true,
      },
      {
        name: "suites",
        label: "Suites",
        kind: "list",
        hint: "APT only, one per line, e.g. bookworm. A dnf or pacman source is described by its address alone.",
      },
      { name: "components", label: "Components", kind: "list", hint: "APT only, one per line, e.g. main." },
      { name: "architectures", label: "Architectures", kind: "list", hint: "One per line; empty takes the host's own." },
      { name: "enabled", label: "Use it right away", kind: "boolean" },
      {
        name: "priority", label: "Priority", kind: "number", min: 0, max: 1000,
        hint: "Which source wins where two offer the same package; zero leaves the manager's own order.",
      },
      {
        name: "gpg_key",
        label: "Public key",
        kind: "textarea",
        hint: "The source's key in its ASCII frame. Without it the host would install whatever comes from that address, scripts included, as root.",
        wide: true,
      },
      {
        name: "allow_unsigned",
        label: "Trust it without checking signatures",
        kind: "boolean",
        hint: "Only for a source that has no key at all, and only over https. It means the host runs whatever that address serves.",
      },
      { name: "username", label: "User name", kind: "text", hint: "For a source behind a login; the password is a reference to the secret store and is typed in the advanced view." },
      {
        name: "remove",
        label: "Remove this source",
        kind: "boolean",
        hint: "Takes the source away together with its key and its password. The address and the rest of the fields are then ignored.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "id", "Give the source an identifier.")) {
        shaped(problems, form, "id", REPOSITORY_ID,
          "An identifier is lower-case letters, digits and . _ - , at least two characters.");
      }
      if (flag(form, "remove")) return problems;
      const url = text(form, "url");
      if (url === "") {
        problems.push({ field: "url", message: "Give the source an address, or say it is to be removed." });
      } else if (!/^https?:\/\/[^\s"']+$/.test(url)) {
        problems.push({ field: "url", message: "A source is fetched over http or https and its address carries no spaces or quotes." });
      } else if (!url.startsWith("https://") && flag(form, "allow_unsigned")) {
        problems.push({ field: "url", message: "A source whose signatures are not checked has to be at least over https." });
      }
      if (!flag(form, "allow_unsigned") && text(form, "gpg_key") === "") {
        problems.push({
          field: "gpg_key",
          message: "A source with signature checking needs its public key; without a key say so explicitly.",
        });
      }
      if (list(form, "components").length > 0 && list(form, "suites").length === 0) {
        problems.push({ field: "suites", message: "An APT source names at least one suite next to its components." });
      }
      const priority = count(form, "priority");
      if (priority < 0 || priority > 1000) {
        problems.push({ field: "priority", message: "The priority lies between 0 and 1000." });
      }
      if (text(form, "username") !== "" && !url.startsWith("https://")) {
        problems.push({ field: "username", message: "A source with a login has to be fetched over https." });
      }
      return problems;
    },
    target: (form) => text(form, "id"),
  }),

  define({
    action: "packages.repair",
    title: "Finish an interrupted package configuration",
    group: GROUP,
    key: "package_repair",
    note: "The operation takes no settings: it finishes what an interrupted transaction left half done. Answers to questions a package asks are typed in the advanced view, one package at a time.",
    fields: [],
    check: () => [],
    target: () => "",
  }),
];
