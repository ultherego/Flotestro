import {
  count, DEFINITION_NAME, define, each, list, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Backups.
 *
 * The data flows from the host straight to the repository and never through
 * the panel. The credentials are references to the secret store: the host
 * reaches for them at execution time and hands them to the tool through the
 * environment rather than as an argument anybody could read in /proc.
 */

const GROUP = "Backups";

const PLAN_NOTE =
  "Every host computes its own plan first: the planning step says which of these directories it really has, how much lies in them, whether the repository answers and what would remain after retention.";

const idField: OperationField = {
  name: "id",
  label: "Definition",
  kind: "text",
  placeholder: "system-nightly",
  hint: "How the panel recognises this backup on every host; the snapshots it makes are marked with it.",
};

const toolField: OperationField = {
  name: "tool",
  label: "Tool",
  kind: "select",
  options: [
    { value: "restic", label: "restic" },
    { value: "borg", label: "borg" },
    { value: "runbook", label: "A script the host administrator put there" },
  ],
};

const repositoryField: OperationField = {
  name: "repository",
  label: "Repository",
  kind: "text",
  wide: true,
  hint: "Where the copy goes. The password is a reference to the secret store and is typed in the advanced view.",
};

const runbookField: OperationField = {
  name: "runbook",
  label: "Script",
  kind: "text",
  hint: "The name of a script already on the host. The panel does not send its content and cannot create it.",
};

function definitionCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "id", "Give the backup a name.")) {
    shaped(problems, form, "id", DEFINITION_NAME,
      "The name is lower-case letters, digits and . _ - , at least two characters.");
  }
  const tool = text(form, "tool");
  if (!["restic", "borg", "runbook"].includes(tool)) {
    problems.push({ field: "tool", message: "Say which tool makes the copy." });
  } else if (tool === "runbook") {
    if (required(problems, form, "runbook", "Name the script on the host.")) {
      shaped(problems, form, "runbook", DEFINITION_NAME, "The script name is lower-case letters, digits and . _ - .");
    }
  } else if (text(form, "repository") === "") {
    problems.push({ field: "repository", message: "Say where the copy goes." });
  }
  return problems;
}

export const backup: OperationEntry[] = [
  define({
    action: "backup.run",
    title: "Make a backup",
    group: GROUP,
    key: "backup",
    plan: PLAN_NOTE,
    fields: [
      idField,
      toolField,
      repositoryField,
      {
        name: "paths", label: "What to copy", kind: "list", wide: true, placeholder: "/etc\n/srv",
        hint: "One absolute path per line. A host that has none of them says so in its plan instead of making an empty copy.",
      },
      { name: "excludes", label: "What to leave out", kind: "list", hint: "One pattern per line." },
      { name: "tags", label: "Tags", kind: "list", hint: "One per line; they mark the snapshot in the repository." },
      { name: "keep_last", label: "Keep the last", kind: "number", min: 0, max: 10000, hint: "How many recent copies survive the clean-up; zero means the rule does not apply." },
      { name: "keep_daily", label: "Keep daily", kind: "number", min: 0, max: 10000 },
      { name: "keep_weekly", label: "Keep weekly", kind: "number", min: 0, max: 10000 },
      { name: "keep_monthly", label: "Keep monthly", kind: "number", min: 0, max: 10000 },
      {
        name: "prune", label: "Delete what falls outside the rules", kind: "boolean",
        hint: "Off leaves old copies in the repository even when the rules no longer keep them.",
      },
      {
        name: "initialize", label: "Create the repository on the first copy", kind: "boolean",
        hint: "Consent to a repository that does not exist yet. Without it a first copy to an empty target fails instead of creating one nobody planned.",
      },
      runbookField,
    ],
    check: (form) => {
      const problems = definitionCheck(form);
      const paths = list(form, "paths");
      if (paths.length === 0 && text(form, "tool") !== "runbook") {
        problems.push({ field: "paths", message: "Say what is to be copied." });
      }
      if (paths.length > 100) {
        problems.push({ field: "paths", message: "One definition covers at most 100 paths." });
      }
      const bad = paths.find((path) => !path.startsWith("/"));
      if (bad !== undefined) {
        problems.push({ field: "paths", message: "{value} is not an absolute path.", params: { value: bad } });
      }
      each(problems, list(form, "tags"), "tags", /^[^\s,]+$/, "{value} is not a tag; a tag has no spaces or commas.");
      for (const field of ["keep_last", "keep_daily", "keep_weekly", "keep_monthly"]) {
        const value = count(form, field);
        if (value < 0 || value > 10000) {
          problems.push({ field, message: "The number of kept copies lies between 0 and 10000." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "id"),
  }),

  define({
    action: "backup.verify",
    title: "Check that a backup can be restored",
    group: GROUP,
    key: "backup",
    plan: "Every host computes its own plan first: the planning step says whether the repository answers, what lies in it and what the check would cost.",
    note: "A backup nobody has ever read back is a hope, not a backup.",
    fields: [
      idField,
      toolField,
      repositoryField,
      {
        name: "read_data", label: "Read the data itself", kind: "boolean",
        hint: "Off checks the structure of the repository alone, which is quick. On reads the contents back, which is the only check that proves anything - and it costs the host and the network.",
      },
      runbookField,
    ],
    check: definitionCheck,
    target: (form) => text(form, "id"),
  }),
];
