import {
  asFlag, asText, body, bounded, COMPOSE_PROJECT, define, flag, formOf, list, pairs,
  payloadOf, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * Containers.
 *
 * A container is named by its identifier and not by its name: a name is a
 * label that can move to another container between the plan and the
 * execution, and the operator approved one specific object. The name
 * travels beside it for the audit trail, so what they saw is what stays in
 * the record.
 */

const GROUP = "Containers";

/** The engine's own identifier: twelve to sixty-four hexadecimal characters. */
const CONTAINER_ID = /^[0-9a-f]{12,64}$/;

const containerField: OperationField = {
  name: "container_id",
  label: "Container",
  kind: "text",
  hint: "The engine's identifier, as the container list shows it. A name may point at a different container by the time the change runs.",
  placeholder: "3f2a9c1b4d55",
};

const nameField: OperationField = {
  name: "name",
  label: "Name it had",
  kind: "text",
  hint: "What the container was called when the order was made; it serves the record alone and changes nothing.",
};

function containerCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "container_id", "Name the container this acts on.")) {
    shaped(problems, form, "container_id", CONTAINER_ID,
      "A container identifier is twelve to sixty-four hexadecimal characters.");
  }
  bounded(problems, form, "timeout_seconds", 1, 3600, "The time to shut down lies between 1 and 3600 seconds.");
  return problems;
}

const stopTimeout: OperationField = {
  name: "timeout_seconds",
  label: "Give it this long to shut down",
  kind: "duration",
  min: 0,
  max: 3600,
  hint: "How long the container may take to stop before it is killed. Zero takes the engine's own.",
};

/**
 * Declared containers, networks and volumes.
 *
 * A declaration says what is to stand on the host, not the steps that
 * would put it there. It is therefore named, not identified: the operator
 * declares "the container called this", and the identifier of whatever
 * carries that name changes with every replacement - which is also why a
 * container that differs is replaced rather than edited, and why the plan
 * says so before anybody approves it.
 *
 * The compact forms are the ones the host reads: a published port is
 * "8080:80/tcp", a mount is "volume:data:/var/lib/data:ro", an attachment
 * is "internal=api@10.0.1.5". The panel checks their shape here and the
 * host reads them with the same code, so the words on the screen mean on
 * the host exactly what they looked like.
 */

const OBJECT_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const PUBLISHED_PORT = /^(\[[0-9A-Fa-f:]{2,45}\]:|[0-9.]{7,15}:)?(\d{0,5}:)?\d{1,5}(\/(tcp|udp|sctp))?$/;
const DECLARED_MOUNT = /^(volume:[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}|bind:\/[^\s:]*|tmpfs):[^\s:]+(:(ro|rw|\d{1,19}))?$/;
const ATTACHMENT = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(=[a-zA-Z0-9][a-zA-Z0-9_.,-]{0,255})?(@[0-9A-Fa-f.:]{2,45})?$/;
/** A secret as the order names it: the store's name, optionally with a version. */
const SECRET_REFERENCE = /^[a-z0-9][a-z0-9._-]{1,62}(#\d{1,9})?$/;
/** A variable name a shell can carry. */
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** The names the host reads as a credential; their values belong in the store. */
const CREDENTIAL_NAME = /secret|password|passwd|token|apikey|api_key|credential/i;

/** The plan every declaration is bound to; the same sentence for all of them. */
const DECLARATION_PLAN =
  "Every host computes its own plan first: what stands there now, what is to stand there and what the change would do. " +
  "The change carries the plan's digest back, and the host computes the plan again right before it - a host somebody " +
  "else changed in the meantime gets no change that was approved for another state.";

/** The order accepts what the host would otherwise refuse. */
const forceField: OperationField = {
  name: "force",
  label: "Carry it out even so",
  kind: "boolean",
  hint: "Accept what the host refuses by default: a network recreated under the containers attached to it, a volume recreated with everything in it, the removal of an object something still holds.",
};

/** The fields of a declared container, named after the description's own. */
const containerFields: OperationField[] = [
  {
    name: "name", label: "Container", kind: "text",
    // A declaration that meets a container of this name replaces it, so
    // the field must not offer a name the panel invented: on some host it
    // is somebody's running service.
    hint: "What the container is to be called, as the host's containers page lists it when the declaration is about one that already stands there. A declaration is about the name: the engine identifier changes with every replacement.",
  },
  {
    name: "image", label: "Image", kind: "text", placeholder: "registry.example.test/team/app:1.4", wide: true,
    hint: "The full reference. A tag is resolved to a digest in the plan and the container is created from that digest, never from the tag as the registry serves it at that moment.",
  },
  {
    name: "command", label: "Command", kind: "list",
    hint: "One argument per line; it replaces the image's own command. Empty leaves the image's.",
  },
  {
    name: "entrypoint", label: "Entry point", kind: "list",
    hint: "One argument per line; it replaces the image's own entry point.",
  },
  {
    name: "env", label: "Environment", kind: "pairs", wide: true,
    hint: "NAME = value, one per line. A value that is a credential does not belong here: this list is stored with the job and shown to whoever may read it.",
  },
  {
    name: "ports", label: "Published ports", kind: "list",
    placeholder: "8080:80/tcp",
    hint: "One per line, as [address:][host port:]container port[/protocol]. Without a host port the engine picks a free one.",
  },
  {
    name: "mounts", label: "Mounts", kind: "list",
    hint: "One per line: volume:<name>:<mount point>, bind:<path on the host>:<mount point> or tmpfs:<mount point>[:<bytes>]. Add :ro for read only. The names are the host's own: its containers page lists the volumes it has.",
  },
  {
    name: "networks", label: "Networks", kind: "list",
    hint: "One per line, as <network>[=alias,alias][@address]. The network is one the host has - its containers page lists them - and a fixed address only works on a network with a range of its own.",
  },
  {
    name: "restart_policy", label: "When it exits", kind: "select",
    options: [
      { value: "no", label: "Leave it stopped" },
      { value: "always", label: "Always start it again" },
      { value: "unless-stopped", label: "Start it again unless it was stopped by hand" },
      { value: "on-failure", label: "Start it again after a failure" },
    ],
  },
  {
    name: "restart_max_retries", label: "How many times after a failure", kind: "number", min: 0, max: 1000,
    hint: "Belongs to the failure policy alone; zero means without a bound.",
  },
  {
    name: "labels", label: "Labels", kind: "pairs", wide: true,
    hint: "name = value, one per line. The panel's own marks and the Compose ones are not written here.",
  },
  {
    name: "health_test", label: "Health check", kind: "list",
    placeholder: "CMD-SHELL",
    hint: "The check as the engine takes it: CMD or CMD-SHELL on the first line, the command on the following ones. Empty leaves the image's own check.",
  },
  {
    name: "health_disable", label: "Turn the image's check off", kind: "boolean",
    hint: "A container without a check is not an unhealthy container, so the two are separate.",
  },
  { name: "health_interval_seconds", label: "Check every", kind: "duration", min: 0, max: 3600 },
  { name: "health_timeout_seconds", label: "Give the check", kind: "duration", min: 0, max: 3600 },
  { name: "health_retries", label: "Failures before unhealthy", kind: "number", min: 0, max: 100 },
  { name: "health_start_period_seconds", label: "Grace after the start", kind: "duration", min: 0, max: 3600 },
  {
    name: "memory_bytes", label: "Memory limit", kind: "number", min: 0,
    hint: "In bytes; zero means no limit, which is what the engine does.",
  },
  { name: "memory_reservation_bytes", label: "Memory reservation", kind: "number", min: 0 },
  {
    name: "nano_cpus", label: "Processor time", kind: "number", min: 0,
    hint: "In billionths of a core: 1500000000 is a core and a half.",
  },
  { name: "pids_limit", label: "Process limit", kind: "number", min: 0 },
  { name: "user", label: "Run as", kind: "text", placeholder: "1000:1000" },
  { name: "working_dir", label: "Working directory", kind: "path" },
  { name: "hostname", label: "Host name inside", kind: "text" },
  {
    name: "read_only_root_filesystem", label: "Read-only root filesystem", kind: "boolean",
    hint: "What the container has to write then goes into a mount.",
  },
  {
    name: "stop_timeout_seconds", label: "Give it this long to shut down", kind: "duration", min: 0, max: 3600,
  },
  {
    name: "stopped", label: "Leave the container stopped", kind: "boolean",
    hint: "The container is to exist and not run. Without it an order that creates a container means to have the service.",
  },
];

/** The names a container description may carry; anything else is not a form. */
const containerNames = containerFields.map((field) => field.name);

const networkFields: OperationField[] = [
  {
    name: "name", label: "Network", kind: "text",
    // A network that exists with other settings is recreated and every
    // attached container loses it, so no invented name is offered here.
    hint: "What the network is to be called, as the host's containers page lists it when the declaration is about one that already stands there. The engine's own - bridge, host, none - are not declared here.",
  },
  {
    name: "driver", label: "Driver", kind: "text", placeholder: "bridge",
    hint: "Empty means bridge, which is the only driver a single host has without a plugin.",
  },
  {
    name: "subnet", label: "Address range", kind: "text", placeholder: "192.0.2.0/24",
    hint: "Taken from your own addressing - the example is a documentation range and matches nothing. Empty leaves the choice to the engine's address manager, and the plan says which range it took.",
  },
  { name: "gateway", label: "Gateway", kind: "text", placeholder: "192.0.2.1" },
  {
    name: "ip_range", label: "Range handed out", kind: "text", placeholder: "192.0.2.128/25",
    hint: "The part of the range the engine gives to containers; it lies inside the address range.",
  },
  { name: "ipv6", label: "Addressing of the second family", kind: "boolean" },
  { name: "ipv6_subnet", label: "IPv6 range", kind: "text", placeholder: "2001:db8::/64" },
  { name: "ipv6_gateway", label: "IPv6 gateway", kind: "text" },
  {
    name: "internal", label: "No way out of the host", kind: "boolean",
    hint: "Containers on this network reach each other and nothing beyond the host.",
  },
  {
    name: "attachable", label: "Open to containers outside the service", kind: "boolean",
  },
  { name: "options", label: "Driver options", kind: "pairs", wide: true },
  { name: "labels", label: "Labels", kind: "pairs", wide: true },
];

const networkNames = networkFields.map((field) => field.name);

const volumeFields: OperationField[] = [
  {
    name: "name", label: "Volume", kind: "text",
    // A volume that exists with another driver is recreated and everything
    // in it is lost, so the field suggests no name of its own.
    hint: "What the volume is to be called, as the host's containers page lists it when the declaration is about one that already stands there.",
  },
  { name: "driver", label: "Driver", kind: "text", placeholder: "local", hint: "Empty means local." },
  { name: "options", label: "Driver options", kind: "pairs", wide: true },
  { name: "labels", label: "Labels", kind: "pairs", wide: true },
];

const volumeNames = volumeFields.map((field) => field.name);

/** The secret references of an order, as the payload carries them. */
function secretsOf(form: FormValue): Record<string, unknown> {
  const references: Record<string, unknown> = {};
  for (const [variable, value] of Object.entries(pairs(form, "env_secrets"))) {
    const hash = value.lastIndexOf("#");
    const version = hash > 0 ? Number(value.slice(hash + 1)) : NaN;
    references[variable] = Number.isInteger(version) && version > 0
      ? { name: value.slice(0, hash), version }
      : { name: value };
  }
  return references;
}

/**
 * The secret references of a payload, back as the lines that produced
 * them. Anything that is not a reference reads as null: a payload the form
 * would half show belongs in the advanced view.
 */
function secretLines(value: unknown): string | null {
  if (value === undefined || value === null) return "";
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const lines: string[] = [];
  for (const [variable, reference] of Object.entries(value as Record<string, unknown>)) {
    if (!reference || typeof reference !== "object" || Array.isArray(reference)) return null;
    const entry = reference as { name?: unknown; version?: unknown };
    if (typeof entry.name !== "string") return null;
    if (entry.version !== undefined && typeof entry.version !== "number") return null;
    const version = typeof entry.version === "number" && entry.version > 0 ? `#${entry.version}` : "";
    lines.push(`${variable} = ${entry.name}${version}`);
  }
  return lines.join("\n");
}

/** The described object of a section, or null when it is not a description. */
function described(value: unknown, names: string[]): Record<string, unknown> | null {
  if (value === undefined || value === null) return {};
  if (typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  for (const name of Object.keys(record)) {
    if (!names.includes(name)) return null;
  }
  return record;
}

/**
 * What a declaration carries beside the description itself.
 *
 * The digest of the plan is not among it: nobody types a digest. It comes
 * from the planning step - the campaign's, or the host page's - and is put
 * into the order there, the same way a Compose deployment gets its own.
 */
function tail(form: FormValue): Record<string, unknown> {
  return flag(form, "force") ? { force: true } : {};
}

function readForce(section: Record<string, unknown>): boolean | null {
  return asFlag(section.force);
}

/** What the fields of a description refuse before the host ever sees it. */
function lineProblems(
  problems: FormProblem[], form: FormValue, field: string, pattern: RegExp, message: string,
): void {
  const bad = list(form, field).find((line) => !pattern.test(line));
  if (bad !== undefined) problems.push({ field, message, params: { value: bad } });
}

function containerCheckDeclared(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "name", "Say what the container is to be called.")) {
    shaped(problems, form, "name", OBJECT_NAME,
      "A container name starts with a letter or a digit and carries letters, digits, underscore, dot and hyphen.");
  }
  if (required(problems, form, "image", "Name the image the container runs.")) {
    const reference = text(form, "image");
    if (/\s/.test(reference) || reference.length > 512) {
      problems.push({ field: "image", message: "An image reference is one word: a name with an optional registry, tag or digest." });
    }
  }
  lineProblems(problems, form, "ports", PUBLISHED_PORT,
    "{value} is not a published port; write it as 8080:80/tcp.");
  lineProblems(problems, form, "mounts", DECLARED_MOUNT,
    "{value} is not a mount; write it as volume:<name>:<mount point>, bind:<path>:<mount point> or tmpfs:<mount point>.");
  lineProblems(problems, form, "networks", ATTACHMENT,
    "{value} is not a network attachment; write it as <network>[=alias,alias][@address].");
  for (const variable of Object.keys(pairs(form, "env"))) {
    if (!VARIABLE_NAME.test(variable)) {
      problems.push({ field: "env", message: "{value} is not the name of an environment variable.", params: { value: variable } });
      break;
    }
    // A value that is a credential would be stored with the job and shown
    // to everyone who may read it. The store exists for exactly this.
    if (CREDENTIAL_NAME.test(variable)) {
      problems.push({
        field: "env",
        message: "{value} looks like a credential; name a secret of the store for it instead of writing the value into the order.",
        params: { value: variable },
      });
      break;
    }
  }
  for (const [variable, reference] of Object.entries(pairs(form, "env_secrets"))) {
    if (!VARIABLE_NAME.test(variable)) {
      problems.push({ field: "env_secrets", message: "{value} is not the name of an environment variable.", params: { value: variable } });
      break;
    }
    if (!SECRET_REFERENCE.test(reference)) {
      problems.push({
        field: "env_secrets",
        message: "{value} is not a secret of the store; write its name, optionally with #version.",
        params: { value: reference },
      });
      break;
    }
  }
  if (body(form, "health_test") !== "") {
    const first = list(form, "health_test")[0];
    if (first !== "CMD" && first !== "CMD-SHELL") {
      problems.push({ field: "health_test", message: "A health check starts with CMD or CMD-SHELL on its own line." });
    } else if (list(form, "health_test").length < 2) {
      problems.push({ field: "health_test", message: "A health check needs the command that runs inside the container." });
    }
  }
  if (flag(form, "health_disable") && body(form, "health_test") !== "") {
    problems.push({ field: "health_test", message: "A check that is turned off carries no command." });
  }
  const retries = form.restart_max_retries;
  if (typeof retries === "number" && retries > 0 && text(form, "restart_policy") !== "on-failure") {
    problems.push({
      field: "restart_max_retries",
      message: "A retry count belongs to the policy that starts the container again after a failure, and to no other.",
    });
  }
  bounded(problems, form, "stop_timeout_seconds", 0, 3600, "The time to shut down lies between 0 and 3600 seconds.");
  return problems;
}

function networkCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "name", "Say what the network is to be called.")) {
    shaped(problems, form, "name", OBJECT_NAME, "A network name carries letters, digits, underscore, dot and hyphen.");
    if (["bridge", "host", "none"].includes(text(form, "name"))) {
      problems.push({ field: "name", message: "That is a network of the engine itself; give yours another name." });
    }
  }
  if (text(form, "gateway") !== "" && text(form, "subnet") === "") {
    problems.push({ field: "gateway", message: "A gateway needs the address range it belongs to." });
  }
  if (text(form, "ip_range") !== "" && text(form, "subnet") === "") {
    problems.push({ field: "ip_range", message: "A range handed out needs the address range it lies in." });
  }
  if ((text(form, "ipv6_subnet") !== "" || text(form, "ipv6_gateway") !== "") && !flag(form, "ipv6")) {
    problems.push({ field: "ipv6", message: "An IPv6 range on a network with IPv6 turned off." });
  }
  if (text(form, "ipv6_gateway") !== "" && text(form, "ipv6_subnet") === "") {
    problems.push({ field: "ipv6_gateway", message: "An IPv6 gateway needs the range it belongs to." });
  }
  return problems;
}

function nameOnlyCheck(what: string) {
  return (form: FormValue): FormProblem[] => {
    const problems: FormProblem[] = [];
    if (required(problems, form, "name", what)) {
      shaped(problems, form, "name", OBJECT_NAME,
        "A name carries letters, digits, underscore, dot and hyphen.");
    }
    return problems;
  };
}

/** A removal: the object is named, not described. */
function removalEntry(action: string, title: string, kind: string, note: string, missing: string): OperationEntry {
  return define({
    action,
    title,
    group: GROUP,
    key: "docker_ensure",
    plan: DECLARATION_PLAN,
    note,
    extra: ["kind"],
    fields: [
      {
        name: "name", label: kind === "network" ? "Network" : "Volume", kind: "text",
        hint: "The name as the host's containers page lists it. Nothing is guessed here: this order removes the object that carries the name.",
      },
      forceField,
    ],
    compose: (form) => ({ kind, name: text(form, "name"), ...tail(form) }),
    read: (section) => {
      if (section.kind !== kind) return null;
      const name = asText(section.name);
      const force = readForce(section);
      if (name === null || force === null) return null;
      return { name, force };
    },
    check: nameOnlyCheck(missing),
    target: (form) => text(form, "name"),
  });
}

const declarations: OperationEntry[] = [
  define({
    action: "docker.container.ensure",
    title: "Declare a container",
    group: GROUP,
    key: "docker_ensure",
    plan: DECLARATION_PLAN,
    note: "A container that differs from the description is replaced, not edited: the engine can change a handful of a running container's settings and refuses the rest. The plan says which settings differ before anybody approves it.",
    extra: ["container", "env_secrets"],
    fields: [
      ...containerFields,
      {
        name: "env_secrets", label: "Variables from the secret store", kind: "pairs", wide: true,
        hint: "NAME = secret[#version], one per line, the name being the one the secret store keeps it under. The reference travels in the order; the host fetches the value right before the container is created, and no record ever holds it.",
      },
      forceField,
    ],
    compose: (form) => {
      const section: Record<string, unknown> = {
        container: payloadOf(containerFields, form), ...tail(form),
      };
      const secrets = secretsOf(form);
      if (Object.keys(secrets).length > 0) section.env_secrets = secrets;
      return section;
    },
    read: (section) => {
      const container = described(section.container, containerNames);
      if (!container) return null;
      const base = formOf(containerFields, container);
      const secrets = secretLines(section.env_secrets);
      const force = readForce(section);
      if (!base || secrets === null || force === null) return null;
      return { ...base, env_secrets: secrets, force };
    },
    check: containerCheckDeclared,
    target: (form) => text(form, "name"),
  }),

  define({
    action: "docker.network.ensure",
    title: "Declare a network",
    group: GROUP,
    key: "docker_ensure",
    plan: DECLARATION_PLAN,
    note: "A network that exists with another driver or another address range cannot be changed - the engine has no such operation - so it is recreated, and every attached container loses it. The plan names each of them.",
    extra: ["network"],
    fields: [...networkFields, forceField],
    compose: (form) => ({ network: payloadOf(networkFields, form), ...tail(form) }),
    read: (section) => {
      const network = described(section.network, networkNames);
      if (!network) return null;
      const base = formOf(networkFields, network);
      const force = readForce(section);
      if (!base || force === null) return null;
      return { ...base, force };
    },
    check: networkCheck,
    target: (form) => text(form, "name"),
  }),

  define({
    action: "docker.volume.ensure",
    title: "Declare a volume",
    group: GROUP,
    key: "docker_ensure",
    plan: DECLARATION_PLAN,
    note: "A volume that exists with another driver or another driver option is recreated, and everything stored in it is lost. The host refuses that unless the order says it accepts it.",
    extra: ["volume"],
    fields: [...volumeFields, forceField],
    compose: (form) => ({ volume: payloadOf(volumeFields, form), ...tail(form) }),
    read: (section) => {
      const volume = described(section.volume, volumeNames);
      if (!volume) return null;
      const base = formOf(volumeFields, volume);
      const force = readForce(section);
      if (!base || force === null) return null;
      return { ...base, force };
    },
    check: nameOnlyCheck("Say what the volume is to be called."),
    target: (form) => text(form, "name"),
  }),

  removalEntry(
    "docker.network.remove", "Remove a network", "network",
    "A network something is still attached to is not removed unless the order says so; the containers then keep running without it and are not reattached.",
    "Name the network to remove.",
  ),

  removalEntry(
    "docker.volume.remove", "Remove a volume", "volume",
    "Everything stored in the volume goes with it. The engine refuses a volume a container still references, whatever the order says.",
    "Name the volume to remove.",
  ),
];

export const docker: OperationEntry[] = [
  define({
    action: "docker.container.start",
    title: "Start a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.container.stop",
    title: "Stop a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField, stopTimeout],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.container.restart",
    title: "Restart a container",
    group: GROUP,
    key: "docker_container",
    fields: [containerField, nameField, stopTimeout],
    check: containerCheck,
    target: (form) => text(form, "name") || text(form, "container_id"),
  }),

  define({
    action: "docker.image.pull",
    title: "Fetch a container image",
    group: GROUP,
    key: "docker_image",
    note: "Only the image is fetched; nothing on the host starts using it until a container is recreated.",
    fields: [
      {
        name: "reference", label: "Image", kind: "text", placeholder: "registry.example.test/team/app:1.4",
        hint: "The full reference, registry included where it is not the default one. Name the tag or the digest: without one the host takes whatever latest points at that day.",
        wide: true,
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "reference", "Name the image to fetch.")) {
        const reference = text(form, "reference");
        if (/\s/.test(reference) || reference.length > 512) {
          problems.push({ field: "reference", message: "An image reference is one word: a name with an optional registry, tag or digest." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "reference"),
  }),

  define({
    action: "docker.compose.deploy",
    title: "Deploy a Compose project",
    group: GROUP,
    key: "compose",
    plan: "Every host computes its own plan first: the planning step resolves the images the manifest names to their digests and returns the digest of the whole plan, and the deployment carries it back. A tag that moved in the meantime stops the deployment.",
    note: "The manifest travels in the order rather than as a reference to a file on the host: the operator approves the content they read.",
    fields: [
      {
        name: "project", label: "Project", kind: "text",
        hint: "The project name the containers are grouped under, as the host's containers page lists it when the project already stands there; lower-case letters, digits, underscore and hyphen.",
      },
      {
        name: "manifest", label: "Compose file", kind: "textarea", wide: true,
        hint: "The whole compose file as it is to stand on the host.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "project", "Give the project a name.")) {
        shaped(problems, form, "project", COMPOSE_PROJECT,
          "A project name is lower-case letters, digits, underscore and hyphen.");
      }
      const manifest = text(form, "manifest");
      if (manifest === "") {
        problems.push({ field: "manifest", message: "Paste the compose file the project is to run from." });
      } else if (manifest.length > 256 * 1024) {
        problems.push({ field: "manifest", message: "The compose file is larger than 256 kB; that is no longer something an approver reads." });
      }
      return problems;
    },
    target: (form) => text(form, "project"),
  }),

  ...declarations,
];
