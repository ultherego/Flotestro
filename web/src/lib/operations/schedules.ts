import {
  cronValid, define, list, required, SCHEDULE_ID, SCHEDULE_USER, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Scheduled jobs.
 */

const GROUP = "Scheduled jobs";

/** Characters cron would read as a second command rather than an argument. */
const SHELL_CHARACTERS = /[|&;<>()$`\\"'\n\r\t*?[\]{}~!#%]/;

const idField: OperationField = {
  name: "id",
  label: "Entry",
  kind: "text",
  hint: "The identifier the panel gave this entry, as the host's schedules page lists it; it names the file the host keeps it in. An entry somebody wrote on the host by hand has none and cannot be named here.",
};

function idCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "id", "Name the entry this acts on.")) {
    shaped(problems, form, "id", SCHEDULE_ID,
      "An identifier is letters, digits, underscore and hyphen, up to 63 characters.");
  }
  return problems;
}

export const schedules: OperationEntry[] = [
  define({
    action: "schedule.ensure",
    title: "Put a scheduled job on the host",
    group: GROUP,
    key: "schedule",
    fields: [
      idField,
      {
        name: "expression",
        label: "When it runs",
        kind: "text",
        hint: "A cron expression of five fields - minute, hour, day of month, month, day of week - or a shortcut such as @daily. Checked here as well, because an entry cron will not understand would simply never run.",
        placeholder: "15 3 * * *",
      },
      {
        name: "command",
        label: "What it runs",
        kind: "list",
        hint: "The program first, by its absolute path, then one argument per line. It is never a shell line: an argument with a shell character would stop being an argument.",
        wide: true,
      },
      {
        name: "user",
        label: "Runs as",
        kind: "text",
        hint: "The account the entry runs under, as it exists on the host. There is no default: an entry for root needs the right to schedule work as root on top of the right to write entries.",
      },
      {
        name: "kind",
        label: "Written as",
        kind: "select",
        hint: "A cron entry is one file in /etc/cron.d; a timer is a .timer and a .service unit under /etc/systemd/system. Left empty it is a cron entry, which is what an order meant before timers could be written; a host without the mechanism refuses the entry and says which one it has.",
        options: [
          { value: "", label: "A cron entry" },
          { value: "timer", label: "A systemd timer" },
          { value: "any", label: "Whichever the host has" },
        ],
      },
      { name: "comment", label: "Comment", kind: "text", hint: "What the entry is for; it is written next to it on the host.", wide: true },
      {
        name: "adopt",
        label: "Take over an entry already on the host",
        kind: "boolean",
        hint: "Without this the panel does not overwrite an entry nobody put in through it.",
      },
    ],
    check: (form) => {
      const problems = idCheck(form);
      const expression = text(form, "expression");
      if (expression === "") {
        problems.push({ field: "expression", message: "Say when the job runs." });
      } else if (!cronValid(expression)) {
        problems.push({
          field: "expression",
          message: "A cron expression has five fields, or is one of @hourly, @daily, @midnight, @weekly, @monthly, @yearly.",
        });
      }
      // Cron runs a job when the day of the month or the day of the week
      // matches, systemd only when both do.
      if (text(form, "kind") === "timer") {
        const fields = expression.trim().split(/\s+/);
        if (fields.length === 5 && fields[2] !== "*" && fields[4] !== "*") {
          problems.push({
            field: "expression",
            message: "A timer runs when the day of the month and the day of the week both match; cron runs when either does. Restrict only one of them, or order the entry as a cron entry.",
          });
        }
      }
      const command = list(form, "command");
      if (command.length === 0) {
        problems.push({ field: "command", message: "Say what the job runs." });
      } else if (!command[0].startsWith("/")) {
        problems.push({ field: "command", message: "The program is named by its absolute path." });
      } else {
        const offending = command.find((argument) => SHELL_CHARACTERS.test(argument));
        if (offending !== undefined) {
          problems.push({
            field: "command",
            message: "The argument {value} carries a shell character; cron would read it as a second command.",
            params: { value: offending },
          });
        }
      }
      if (required(problems, form, "user", "Say which account the job runs as; root is not a default.")) {
        shaped(problems, form, "user", SCHEDULE_USER,
          "An account name is lower-case letters, digits, underscore and hyphen.");
      }
      return problems;
    },
    target: (form) => text(form, "id"),
  }),

  define({
    action: "schedule.disable",
    title: "Switch a scheduled job off or on",
    group: GROUP,
    key: "schedule",
    fields: [
      idField,
      {
        name: "enabled",
        label: "Let it run",
        kind: "boolean",
        hint: "Off stops the entry from running and leaves everything in it where it is; on lets it run again.",
      },
    ],
    check: idCheck,
    target: (form) => text(form, "id"),
  }),

  define({
    action: "schedule.remove",
    title: "Take a scheduled job off the host",
    group: GROUP,
    key: "schedule",
    fields: [idField],
    check: idCheck,
    target: (form) => text(form, "id"),
  }),

  define({
    action: "schedule.run_now",
    title: "Run a scheduled job now",
    group: GROUP,
    key: "schedule",
    note: "The entry runs once, straight away, under the account it is scheduled for. Its schedule is not touched.",
    fields: [idField],
    check: idCheck,
    target: (form) => text(form, "id"),
  }),
];
