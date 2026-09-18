import { accounts } from "./accounts";
import { backup } from "./backup";
import { certificates } from "./certificates";
import { directory } from "./directory";
import { docker } from "./docker";
import { files } from "./files";
import { network } from "./network";
import { packages } from "./packages";
import { schedules } from "./schedules";
import { security } from "./security";
import { storage } from "./storage";
import { system } from "./system";
import { units } from "./units";
import { emptyForm, type FormValue, type OperationEntry } from "./fields";

export * from "./fields";

/**
 * The registry of operation forms.
 *
 * One entry per operation, assembled from the module files: what the
 * operation is called, which fields it has, how they become the payload and
 * what the panel refuses before the server ever sees it. The Bulk wizard
 * and a host page draw from this same registry, so an operation gains a
 * form once rather than once per screen.
 *
 * An operation missing here is not a refusal - it is an operation whose
 * payload is still typed as JSON. The screens say so where it happens.
 */
export const OPERATION_FORMS: OperationEntry[] = [
  ...units, ...packages, ...files, ...schedules, ...accounts, ...network,
  ...storage, ...docker, ...security, ...certificates, ...backup, ...directory, ...system,
];

const byAction = new Map<string, OperationEntry>(
  OPERATION_FORMS.map((entry) => [entry.action, entry] as const),
);

/** The form of an operation, or undefined where the registry has none yet. */
export function operationForm(action: string | undefined): OperationEntry | undefined {
  return action ? byAction.get(action) : undefined;
}

/** The operations the registry can draw, by module, in the order they were written. */
export function operationGroups(): { group: string; entries: OperationEntry[] }[] {
  const groups: { group: string; entries: OperationEntry[] }[] = [];
  for (const entry of OPERATION_FORMS) {
    const existing = groups.find((candidate) => candidate.group === entry.group);
    if (existing) existing.entries.push(entry);
    else groups.push({ group: entry.group, entries: [entry] });
  }
  return groups;
}

/** The form of an untouched operation. */
export function startingForm(action: string | undefined): FormValue {
  const entry = operationForm(action);
  return entry ? emptyForm(entry) : {};
}

/**
 * The form a payload written as JSON fills in, or null when it is not JSON,
 * not an object, or carries something the fields cannot show. Null is what
 * keeps such a payload in the advanced view instead of quietly losing half
 * of it.
 */
export function readPayloadText(entry: OperationEntry, raw: string): FormValue | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  return entry.fromPayload(parsed as Record<string, unknown>);
}

/** The payload of a form, as the advanced view shows it. */
export function payloadTextOf(entry: OperationEntry, form: FormValue): string {
  return JSON.stringify(entry.toPayload(form), null, 2);
}
