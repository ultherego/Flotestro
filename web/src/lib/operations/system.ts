import {
  AGENT_VERSION, bounded, define, each, hostnameValid, KERNEL_MODULE, list, malformedPairs, pairs,
  required, SHA256, shaped, SYSCTL_KEY, text, TIME_HOST, TIME_ZONE,
  type FormProblem, type OperationEntry,
} from "./fields";

/**
 * The host itself: the kernel, the clock, the name, the reboot and the
 * agent that carries all the rest.
 */

const GROUP = "System";

/** The sysctl branches the panel writes in; anything else is somebody else's. */
const SYSCTL_NAMESPACES = ["vm.", "net.", "fs.", "kernel.", "user."];

/**
 * Kernel modules the panel does not block, and the sentence each refusal
 * says. The whole sentence is written out rather than assembled from a
 * reason, because a sentence put together from pieces exists in one
 * language only.
 */
const PROTECTED_MODULES: Record<string, string> = {
  ext4: "The panel does not block {value}: without it the host cannot mount its own root.",
  xfs: "The panel does not block {value}: without it the host cannot mount its own root.",
  dm_mod: "The panel does not block {value}: without it the LVM volumes, the root among them, do not come up.",
  "dm-mod": "The panel does not block {value}: without it the LVM volumes, the root among them, do not come up.",
  virtio_net: "The panel does not block {value}: without it a virtual machine loses its network.",
  virtio_blk: "The panel does not block {value}: without it a virtual machine loses its disk.",
  e1000: "The panel does not block {value}: without it the host may lose its only network card.",
  nf_tables: "The panel does not block {value}: without it the host firewall stops working.",
};

export const system: OperationEntry[] = [
  define({
    action: "sysctl.ensure",
    title: "Set kernel parameters",
    group: GROUP,
    key: "kernel",
    note: "The settings are written to the panel's own file, so a value somebody put elsewhere is visible as a difference instead of being overwritten in silence.",
    fields: [
      {
        name: "settings", label: "Settings", kind: "pairs", wide: true,
        placeholder: "net.ipv4.ip_forward = 1",
        hint: "One setting per line, written as name = value. The panel writes in the vm, net, fs, kernel and user branches.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      const malformed = malformedPairs(form, "settings");
      if (malformed.length > 0) {
        problems.push({ field: "settings", message: "The line {value} names no value; write it as name = value.", params: { value: malformed[0] } });
        return problems;
      }
      const settings = pairs(form, "settings");
      const keys = Object.keys(settings);
      if (keys.length === 0) {
        problems.push({ field: "settings", message: "Name at least one setting." });
        return problems;
      }
      if (keys.length > 50) {
        problems.push({ field: "settings", message: "One order covers at most 50 settings." });
        return problems;
      }
      for (const key of keys) {
        if (!SYSCTL_KEY.test(key)) {
          problems.push({ field: "settings", message: "{value} is not a setting name.", params: { value: key } });
          return problems;
        }
        if (!SYSCTL_NAMESPACES.some((namespace) => key.startsWith(namespace))) {
          problems.push({
            field: "settings",
            message: "The panel writes in the branches vm. net. fs. kernel. user. ; {value} is outside them.",
            params: { value: key },
          });
          return problems;
        }
        if (/[\n"]/.test(settings[key])) {
          problems.push({ field: "settings", message: "The value of {value} carries a character the file would not keep.", params: { value: key } });
          return problems;
        }
      }
      return problems;
    },
    target: (form) => Object.keys(pairs(form, "settings")).join(", "),
  }),

  define({
    action: "kernel.module.load",
    title: "Load a kernel module",
    group: GROUP,
    key: "kernel",
    fields: [
      {
        name: "module", label: "Module", kind: "text", placeholder: "br_netfilter",
        hint: "The module name as the kernel knows it.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "module", "Name the module.")) {
        shaped(problems, form, "module", KERNEL_MODULE,
          "A module name is lower-case letters, digits, underscore and hyphen.");
      }
      return problems;
    },
    target: (form) => text(form, "module"),
  }),

  define({
    action: "kernel.module.blacklist",
    title: "Block a kernel module from loading",
    group: GROUP,
    key: "kernel",
    plan: "Every host computes its own plan first: the planning step says whether the entry is already there, whether the module is loaded now and who is holding it - because then the entry only takes effect after a reboot.",
    fields: [
      { name: "module", label: "Module", kind: "text", placeholder: "usb_storage" },
      {
        name: "blacklist", label: "Block it", kind: "boolean",
        hint: "On writes the entry that stops the module loading, directly or as somebody else's dependency. Off takes the entry away.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "module", "Name the module.")) {
        shaped(problems, form, "module", KERNEL_MODULE,
          "A module name is lower-case letters, digits, underscore and hyphen.");
        const refusal = PROTECTED_MODULES[text(form, "module")];
        if (refusal) {
          problems.push({ field: "module", message: refusal, params: { value: text(form, "module") } });
        }
      }
      return problems;
    },
    target: (form) => text(form, "module"),
  }),

  define({
    action: "time.config.apply",
    title: "Set where the host takes its time from",
    group: GROUP,
    key: "time",
    plan: "Every host computes its own plan first: the planning step says which time daemon it runs, whether it will reload its sources or restart, and whether the panel would be adding its own directory to somebody else's file.",
    fields: [
      {
        name: "servers", label: "Time servers", kind: "list", wide: true, placeholder: "ntp1.example.com",
        hint: "One address or name per line, at most eight. An empty list is not a way of clearing the sources: a host without a time source drifts and says nothing.",
      },
      {
        name: "allow_step", label: "Allow the clock to jump", kind: "boolean",
        hint: "Without it a host whose time is far out refuses the correction instead of moving the clock under running services.",
      },
      {
        name: "enable_dropin", label: "Let the panel add its directory to the daemon's file", kind: "boolean",
        hint: "For a host whose configuration includes no directory of its own. Without it such a host stays read-only: the panel does not write itself into somebody else's file unasked.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      const servers = list(form, "servers");
      if (servers.length === 0) {
        problems.push({ field: "servers", message: "Name at least one time server." });
        return problems;
      }
      if (servers.length > 8) {
        problems.push({ field: "servers", message: "The panel takes at most eight time servers." });
        return problems;
      }
      each(problems, servers, "servers", TIME_HOST, "{value} is neither an address nor a host name.");
      const seen = new Set<string>();
      const repeated = servers.find((server) => (seen.has(server) ? true : (seen.add(server), false)));
      if (repeated !== undefined) {
        problems.push({ field: "servers", message: "{value} is on the list twice.", params: { value: repeated } });
      }
      return problems;
    },
    target: (form) => list(form, "servers").join(", "),
  }),

  define({
    action: "time.timezone.set",
    title: "Set the host's time zone",
    group: GROUP,
    key: "time",
    fields: [
      {
        name: "timezone", label: "Time zone", kind: "text", placeholder: "Europe/Warsaw",
        hint: "As the zone database names it. It changes what the host's logs and scheduled jobs read as local time.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "timezone", "Name the time zone.")) {
        const zone = text(form, "timezone");
        if (zone.includes("..") || !TIME_ZONE.test(zone) || zone.length > 64) {
          problems.push({ field: "timezone", message: "A zone is named like Europe/Warsaw or UTC." });
        }
      }
      return problems;
    },
    target: (form) => text(form, "timezone"),
  }),

  define({
    action: "system.hostname.set",
    title: "Rename the host",
    group: GROUP,
    key: "hostname",
    note: "Across the fleet a rename carries one new name per host and nothing shared: the bulk workspace asks for that mapping instead of this field, because a shared name is the one thing a rename must never set.",
    fields: [
      {
        name: "hostname", label: "New name", kind: "text", placeholder: "web-01.corp.example.com",
        hint: "In lower case, as a plain label or a fully qualified name. Whatever looks this host up by its old name will stop finding it.",
      },
      { name: "pretty", label: "Readable name", kind: "text", hint: "What a person sees next to the host; optional and free-form." },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "hostname", "Give the host its new name.")) {
        if (!hostnameValid(text(form, "hostname"))) {
          problems.push({
            field: "hostname",
            message: "A name is lower-case labels of letters, digits and hyphens, at most 64 characters, and it is not localhost.",
          });
        }
      }
      if (/[\r\n]/.test(text(form, "pretty")) || text(form, "pretty").length > 255) {
        problems.push({ field: "pretty", message: "The readable name is one line of at most 255 characters." });
      }
      return problems;
    },
    target: (form) => text(form, "hostname"),
  }),

  define({
    action: "system.reboot",
    title: "Reboot the host",
    group: GROUP,
    key: "reboot",
    note: "The task is settled by the host coming back with a new boot identifier, not by the command being sent. A host that never returns fails; it does not pass as done.",
    fields: [
      {
        name: "delay_seconds", label: "Wait before rebooting", kind: "duration", min: 0, max: 3600,
        hint: "Time for sessions to close and the result to travel back before the host leaves the network. Zero reboots straight away.",
      },
      { name: "reason", label: "Reason", kind: "text", wide: true, hint: "What the host writes in its own log before it goes down." },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      bounded(problems, form, "delay_seconds", 1, 3600, "The delay is at most an hour.");
      return problems;
    },
    target: () => "",
  }),

  define({
    action: "agent.upgrade",
    title: "Replace the agent with another version",
    group: GROUP,
    key: "agent_upgrade",
    note: "What settles the task is the host reporting back in with the version asked for. The package manager's exit code says only that the transaction went through, not that the host came back.",
    fields: [
      {
        name: "target_version", label: "Version to run", kind: "text", placeholder: "0.54.0",
        hint: "The version that has to report in after the restart.",
      },
      {
        name: "package_sha256", label: "Package checksum", kind: "text", wide: true,
        hint: "The SHA-256 from the release. The manager checks the repository's signature; this is the panel's own, independent check.",
      },
      {
        name: "rollback_version", label: "Fall back to", kind: "text",
        hint: "The version to return to when the host does not come back with the new one. Empty means no prepared return.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "target_version", "Name the version the host is to run.")) {
        shaped(problems, form, "target_version", AGENT_VERSION,
          "That is not a package version: letters, digits and . - + ~ : _ .");
      }
      shaped(problems, form, "rollback_version", AGENT_VERSION,
        "That is not a package version: letters, digits and . - + ~ : _ .");
      shaped(problems, form, "package_sha256", SHA256,
        "A checksum is sixty-four hexadecimal characters.");
      return problems;
    },
    target: (form) => text(form, "target_version"),
  }),
];
