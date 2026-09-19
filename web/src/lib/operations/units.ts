import {
  define, required, shaped, text, UNIT_NAME,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * The systemd units. Every operation here names one unit.
 */

const GROUP = "Services";

const unitField: OperationField = {
  name: "unit",
  label: "Unit",
  kind: "unit",
  // A unit is named by the host that carries it, and the same job runs under
  // a different unit on another distribution.
  hint: "The systemd unit this acts on, with its suffix, exactly as the host's services page lists it.",
};

/** The name of a unit is required and has to be one systemd would accept. */
function unitCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "unit", "Name the unit this acts on.")) {
    shaped(problems, form, "unit", UNIT_NAME,
      "A unit name ends in .service, .socket, .timer, .target, .path, .mount, .automount, .swap, .slice or .scope.");
  }
  return problems;
}

/** An operation that names a unit and nothing else. */
function unitOperation(action: string, title: string): OperationEntry {
  return define({
    action, title, group: GROUP, key: "unit",
    fields: [unitField],
    check: unitCheck,
    target: (form) => text(form, "unit"),
  });
}

export const units: OperationEntry[] = [
  unitOperation("unit.start", "Start a service"),
  unitOperation("unit.stop", "Stop a service"),
  unitOperation("unit.restart", "Restart a service"),
  unitOperation("unit.reload", "Make a service reread its configuration"),
  unitOperation("unit.reset_failed", "Clear a unit's failed state"),

  define({
    action: "unit.enable.set",
    title: "Decide whether a service starts at boot",
    group: GROUP,
    key: "unit_toggle",
    fields: [
      unitField,
      {
        name: "enabled",
        label: "Start it at boot",
        kind: "boolean",
        hint: "On writes the boot-time link, off takes it away. The running service is left as it is either way; this is about the next boot.",
      },
    ],
    check: unitCheck,
    target: (form) => text(form, "unit"),
  }),

  define({
    action: "unit.mask.set",
    title: "Block a service from ever starting",
    group: GROUP,
    key: "unit_toggle",
    fields: [
      unitField,
      {
        name: "enabled",
        label: "Block it",
        kind: "boolean",
        hint: "On points the unit at nothing, so neither a boot nor an operator nor another unit can start it. Off gives it back.",
      },
    ],
    check: unitCheck,
    target: (form) => text(form, "unit"),
  }),
];
