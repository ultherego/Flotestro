/**
 * The vocabulary every operation form is written in.
 */

/** What a field means for the value behind it. */
export type FieldKind =
  /** One line of text. */
  | "text"
  /** Several lines that travel as one string, e.g. a file's content. */
  | "textarea"
  /** A whole number. */
  | "number"
  /** A number of seconds. */
  | "duration"
  /** A flag the operator turns on. */
  | "boolean"
  /** One of a fixed set of values. */
  | "select"
  /** A list of strings, one per line. */
  | "list"
  /** A list of package names, one per line or separated by commas. */
  | "packages"
  /** Key and value pairs, "name = value" per line. */
  | "pairs"
  /** The name of a systemd unit. */
  | "unit"
  /** An absolute path on the host. */
  | "path";

/** One choice of a select field. */
export type FieldOption = { value: string; label: string };

/** The value of one field, as the form keeps it. */
export type FieldValue = string | number | boolean;

/** The whole form: every field under its own name. */
export type FormValue = Record<string, FieldValue>;

/**
 * What is wrong with the form; a problem without a field is about the whole
 * order.
 */
export type FormProblem = {
  field?: string;
  message: string;
  params?: Record<string, string | number>;
};

/**
 * One field of a form. The name is the payload's own field name wherever the
 * shapes agree, so a form and the JSON it produces read as the same thing.
 */
export type OperationField = {
  name: string;
  label: string;
  kind: FieldKind;
  hint?: string;
  placeholder?: string;
  options?: FieldOption[];
  /** Whether the field takes the full width of the grid. */
  wide?: boolean;
  min?: number;
  max?: number;
  /** The value an untouched form starts from; without one the kind decides. */
  default?: FieldValue;
};

/**
 * What a host really has, for the fields that name something on it.
 */
export type FieldSuggestions = Record<string, string[]>;

/**
 * The registry entry of one operation: everything a screen needs to let an
 * operator order it without writing JSON.
 */
export type OperationEntry = {
  action: string;
  /** What the operation does, as a person would say it. */
  title: string;
  /** The module the operation belongs to; screens group by it. */
  group: string;
  fields: OperationField[];
  /** A sentence about the plan the change is bound to, where there is one. */
  plan?: string;
  /** A sentence about the operation itself, where the fields do not say enough. */
  note?: string;
  /** The payload the form produces, in the shape the API takes. */
  toPayload: (form: FormValue) => Record<string, unknown>;
  /** The form a payload fills in, or null when the fields cannot show it. */
  fromPayload: (payload: Record<string, unknown>) => FormValue | null;
  /**
   * What the payload acts on - the unit, the path, the packages.
   */
  summary: (payload: Record<string, unknown>) => string;
  validate: (form: FormValue) => FormProblem[];
};

/** The value an untouched field of this kind starts from. */
function blank(kind: FieldKind): FieldValue {
  switch (kind) {
    case "number":
    case "duration":
      return 0;
    case "boolean":
      return false;
    default:
      return "";
  }
}

/** The form of an operation before anything is typed into it. */
export function emptyForm(entry: OperationEntry): FormValue {
  const value: FormValue = {};
  for (const field of entry.fields) value[field.name] = field.default ?? blank(field.kind);
  return value;
}

/* Reading the form. Every reader is total: a value of the wrong type reads
   as an empty one, because a draft kept by an older release may carry
   anything and a form must still draw. */

/** One line of text, without the spaces around it. */
export function text(form: FormValue, name: string): string {
  const value = form[name];
  return typeof value === "string" ? value.trim() : "";
}

/** Text kept exactly as typed: a file's content, a manifest, a key. */
export function body(form: FormValue, name: string): string {
  const value = form[name];
  return typeof value === "string" ? value : "";
}

export function flag(form: FormValue, name: string): boolean {
  return form[name] === true;
}

export function count(form: FormValue, name: string): number {
  const value = form[name];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** The lines of a list field, trimmed, without the empty ones. */
export function list(form: FormValue, name: string): string[] {
  return body(form, name)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** A list of names typed one per line, by commas or simply spaced apart. */
export function words(form: FormValue, name: string): string[] {
  return body(form, name)
    .split(/[\s,;]+/)
    .map((word) => word.trim())
    .filter((word) => word !== "");
}

/** The "name = value" lines of a pairs field; a line without a value is left out. */
export function pairs(form: FormValue, name: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of body(form, name).split("\n")) {
    if (line.trim() === "") continue;
    const index = line.indexOf("=");
    if (index <= 0) continue;
    const key = line.slice(0, index).trim();
    if (key !== "") result[key] = line.slice(index + 1).trim();
  }
  return result;
}

/** The lines of a pairs field that name no value; the validator reports them. */
export function malformedPairs(form: FormValue, name: string): string[] {
  return body(form, name)
    .split("\n")
    .filter((line) => line.trim() !== "" && line.indexOf("=") <= 0);
}

/* Reading a payload back into the form. Every reader returns null for a
   value it cannot show, and null travels up: a payload the fields would
   silently lose part of belongs in the advanced view, not in the form. */

export function asText(value: unknown): string | null {
  if (value === undefined || value === null) return "";
  return typeof value === "string" ? value : null;
}

export function asFlag(value: unknown): boolean | null {
  if (value === undefined || value === null) return false;
  return typeof value === "boolean" ? value : null;
}

export function asCount(value: unknown): number | null {
  if (value === undefined || value === null) return 0;
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function asList(value: unknown): string | null {
  if (value === undefined || value === null) return "";
  if (!Array.isArray(value)) return null;
  if (value.some((entry) => typeof entry !== "string")) return null;
  return (value as string[]).join("\n");
}

export function asPairs(value: unknown): string | null {
  if (value === undefined || value === null) return "";
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const lines: string[] = [];
  for (const key of Object.keys(record)) {
    const entry = record[key];
    if (typeof entry !== "string") return null;
    lines.push(`${key} = ${entry}`);
  }
  return lines.join("\n");
}

/**
 * The one sub-payload an operation carries, or null when the payload is
 * shaped differently or carries a field these forms do not know.
 */
export function sub(
  payload: Record<string, unknown>, key: string, known: string[],
): Record<string, unknown> | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const keys = Object.keys(payload);
  if (keys.length !== 1 || keys[0] !== key) return null;
  const section = payload[key];
  if (!section || typeof section !== "object" || Array.isArray(section)) return null;
  const record = section as Record<string, unknown>;
  for (const name of Object.keys(record)) {
    if (!known.includes(name)) return null;
  }
  return record;
}

/**
 * The sub-payload of a form whose fields are named after the payload's own
 * fields: every value that says something, under its own name.
 */
export function payloadOf(fields: OperationField[], form: FormValue): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const field of fields) {
    switch (field.kind) {
      case "boolean": {
        if (flag(form, field.name)) result[field.name] = true;
        break;
      }
      case "number":
      case "duration": {
        const value = count(form, field.name);
        if (value !== 0) result[field.name] = value;
        break;
      }
      case "list": {
        const value = list(form, field.name);
        if (value.length > 0) result[field.name] = value;
        break;
      }
      case "packages": {
        const value = words(form, field.name);
        if (value.length > 0) result[field.name] = value;
        break;
      }
      case "pairs": {
        const value = pairs(form, field.name);
        if (Object.keys(value).length > 0) result[field.name] = value;
        break;
      }
      case "textarea": {
        const value = body(form, field.name);
        if (value !== "") result[field.name] = value;
        break;
      }
      default: {
        const value = text(form, field.name);
        if (value !== "") result[field.name] = value;
      }
    }
  }
  return result;
}

/** The form a sub-payload fills in, or null when a field cannot show its value. */
export function formOf(fields: OperationField[], section: Record<string, unknown>): FormValue | null {
  const result: FormValue = {};
  for (const field of fields) {
    const raw = section[field.name];
    let value: FieldValue | null;
    switch (field.kind) {
      case "boolean":
        value = asFlag(raw);
        break;
      case "number":
      case "duration":
        value = asCount(raw);
        break;
      case "list":
      case "packages":
        value = asList(raw);
        break;
      case "pairs":
        value = asPairs(raw);
        break;
      default:
        value = asText(raw);
    }
    if (value === null) return null;
    result[field.name] = value;
  }
  return result;
}

/** How an entry is written down; `define` turns it into the entry itself. */
type Definition = {
  action: string;
  title: string;
  group: string;
  /** The key of the sub-payload, e.g. "unit_toggle". */
  key: string;
  fields: OperationField[];
  plan?: string;
  note?: string;
  /** Payload fields the form handles by hand, beyond the ones it is named after. */
  extra?: string[];
  /** The sub-payload, where the fields alone do not compose it. */
  compose?: (form: FormValue) => Record<string, unknown>;
  /** The form a sub-payload fills in, where the fields alone do not read it. */
  read?: (section: Record<string, unknown>) => FormValue | null;
  /** What the operation acts on; without one the first field names it. */
  target?: (form: FormValue) => string;
  check?: (form: FormValue) => FormProblem[];
};

/**
 * Turns a written-down operation into a registry entry.
 */
export function define(definition: Definition): OperationEntry {
  const known = [...definition.fields.map((field) => field.name), ...(definition.extra ?? [])];
  const entry: OperationEntry = {
    action: definition.action,
    title: definition.title,
    group: definition.group,
    fields: definition.fields,
    plan: definition.plan,
    note: definition.note,
    toPayload: (form) => ({
      [definition.key]: definition.compose
        ? definition.compose(form)
        : payloadOf(definition.fields, form),
    }),
    fromPayload: (payload) => {
      const section = sub(payload, definition.key, known);
      if (!section) return null;
      return definition.read ? definition.read(section) : formOf(definition.fields, section);
    },
    summary: (payload) => {
      const form = entry.fromPayload(payload);
      if (!form) return "";
      if (definition.target) return definition.target(form);
      const first = definition.fields[0];
      return first ? String(form[first.name] ?? "") : "";
    },
    validate: (form) => (definition.check ? definition.check(form) : []),
  };
  return entry;
}

/* The shapes the server checks its side. They are repeated here so a form
   cannot compose an order the server would refuse as malformed - the panel
   refuses early, the host conclusively. */

export const UNIT_NAME = /^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|target|path|mount|automount|swap|slice|scope)$/;
export const PACKAGE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9+._-]*$/;
export const ACCOUNT_NAME = /^[a-z_][a-z0-9_-]{0,31}\$?$/;
export const SCHEDULE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/;
export const SCHEDULE_USER = /^[a-z_][a-z0-9_-]{0,31}$/;
export const INTERFACE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$/;
export const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
export const ANCHOR_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const DEFINITION_NAME = /^[a-z0-9][a-z0-9._-]{1,63}$/;
export const COMPOSE_PROJECT = /^[a-z0-9][a-z0-9_-]{0,62}$/;
export const FIREWALL_ZONE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,16}$/;
export const FIREWALL_SERVICE = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
export const FIREWALL_RULE = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const DURABLE_SOURCE = /^(UUID|PARTUUID|LABEL|PARTLABEL)=[A-Za-z0-9._:-]{1,64}$/;
export const DEVICE_PATH = /^\/dev\/[A-Za-z0-9/._-]{1,120}$/;
export const FILESYSTEM_TYPE = /^[a-z0-9]{1,16}$/;
export const MOUNT_OPTIONS = /^[A-Za-z0-9=,._:/@%+-]{0,256}$/;
export const LVM_SIZE = /^\+\d{1,9}[KMGTkmgt]$|^\+\d{1,3}%(FREE|VG|PVS)$/;
export const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const SYSCTL_KEY = /^[a-z0-9_]+(\.[a-z0-9_*-]+){1,8}$/;
export const KERNEL_MODULE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export const AGENT_VERSION = /^[0-9a-zA-Z.+~:_-]{1,64}$/;
export const SHA256 = /^[0-9a-f]{64}$/;
export const TIME_ZONE = /^[A-Za-z][A-Za-z0-9+_-]*(\/[A-Za-z0-9+_.-]+){0,2}$/;
export const TIME_HOST = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
export const DOMAIN_NAME = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
export const SSH_ACCOUNT = /^[A-Za-z0-9_.*?@-]{1,64}$/;
export const REPOSITORY_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/;
export const EXPIRY_DATE = /^\d{4}-\d{2}-\d{2}$/;
export const PORT_RANGE = /^(\d{1,5})(?:-(\d{1,5}))?$/;

/** The public key types the panel accepts; the rest is not a key it can place. */
export const KEY_TYPES = [
  "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
];

/** The cron shortcuts the host's parser expands; @reboot has no calendar moment. */
const CRON_SHORTCUTS = ["@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"];

/* Small checkers the entries share. Each one appends at most one problem,
   so a field says one thing at a time rather than a list the operator has
   to read to the end. */

export function required(problems: FormProblem[], form: FormValue, field: string, message: string): boolean {
  if (text(form, field) === "" && body(form, field) === "") {
    problems.push({ field, message });
    return false;
  }
  return true;
}

export function shaped(
  problems: FormProblem[], form: FormValue, field: string, pattern: RegExp, message: string,
): void {
  const value = text(form, field);
  if (value !== "" && !pattern.test(value)) problems.push({ field, message });
}

export function absolute(problems: FormProblem[], form: FormValue, field: string, message: string): void {
  const value = text(form, field);
  if (value === "") return;
  if (!value.startsWith("/") || value.includes("..") || /[\n\t*?]/.test(value)) {
    problems.push({ field, message });
  }
}

export function each(
  problems: FormProblem[], values: string[], field: string, pattern: RegExp, message: string,
): void {
  for (const value of values) {
    if (!pattern.test(value)) {
      problems.push({ field, message, params: { value } });
      return;
    }
  }
}

export function bounded(
  problems: FormProblem[], form: FormValue, field: string, min: number, max: number, message: string,
): void {
  const value = count(form, field);
  if (value === 0) return;
  if (!Number.isInteger(value) || value < min || value > max) problems.push({ field, message });
}

/** Whether a cron expression is one the host would understand. */
export function cronValid(expression: string): boolean {
  const trimmed = expression.trim().toLowerCase();
  if (trimmed === "") return false;
  if (CRON_SHORTCUTS.includes(trimmed)) return true;
  if (trimmed.startsWith("@")) return false;
  return trimmed.split(/\s+/).length === 5;
}

/** Whether a line is a public key the panel would place in a file. */
export function publicKeyValid(line: string): boolean {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.includes("PRIVATE KEY")) return false;
  const parts = trimmed.split(/\s+/);
  // A key may come with options in front of the type, as the file allows;
  // the type is then the first field the panel recognises.
  const start = parts.findIndex((part) => KEY_TYPES.includes(part));
  return start >= 0 && parts.length >= start + 2;
}

/** Whether a port or a port range fits what the firewall takes. */
export function portValid(port: string): boolean {
  const parts = PORT_RANGE.exec(port);
  if (!parts) return false;
  const from = Number(parts[1]);
  if (from < 1 || from > 65535) return false;
  if (parts[2] === undefined) return true;
  const to = Number(parts[2]);
  return to >= 1 && to <= 65535 && to > from;
}

/** Whether an address carries a mask, as a firewall source has to. */
export function cidrValid(source: string): boolean {
  const [address, mask, ...rest] = source.split("/");
  if (rest.length > 0 || mask === undefined || address === "") return false;
  const bits = Number(mask);
  if (!Number.isInteger(bits) || bits < 0) return false;
  if (address.includes(":")) return bits <= 128;
  const octets = address.split(".");
  return bits <= 32 && octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

/** Whether a value is an IP address, which is what a resolver or a gateway takes. */
export function addressValid(value: string): boolean {
  if (value.includes(":")) return /^[0-9A-Fa-f:.]{2,45}$/.test(value);
  const octets = value.split(".");
  return octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

/** Whether a value is an address with a prefix, as an interface's own address is. */
export function prefixedAddressValid(value: string): boolean {
  return cidrValid(value);
}

/** Whether a hostname is one the host would keep as written. */
export function hostnameValid(name: string): boolean {
  if (name === "" || name.length > 64) return false;
  if (name !== name.toLowerCase()) return false;
  if (name === "localhost" || name.endsWith(".localhost")) return false;
  return name.split(".").every((part) => HOST_LABEL.test(part));
}
