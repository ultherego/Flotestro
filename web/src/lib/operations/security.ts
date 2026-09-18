import {
  cidrValid, define, each, FIREWALL_RULE, FIREWALL_SERVICE, FIREWALL_ZONE, INTERFACE_NAME, list,
  portValid, required, shaped, SSH_ACCOUNT, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * The firewall, the SSH server and mandatory access control.
 *
 * These are the changes that lock an operator out of the host they are
 * changing. The panel protects its own channel by default and asks for an
 * explicit decision before it lets a change close it - because the result
 * is sometimes a host somebody has to drive to.
 */

const GROUP = "Security";

const FIREWALL_PLAN =
  "Every host computes its own difference first: the planning step shows the rule set it has now, and the change is bound to it. A set changed in the meantime stops the change instead of landing between somebody else's rules.";

const breakGlassField: OperationField = {
  name: "break_glass",
  label: "Allow it to close the panel's own way in",
  kind: "boolean",
  hint: "Without it a change that would cut the management channel is refused. With it, a host that goes silent is a host somebody visits.",
};

const rollbackField: OperationField = {
  name: "rollback_seconds",
  label: "Put it back after",
  kind: "duration",
  min: 0,
  max: 3600,
  hint: "How long the host waits for the panel to confirm it is still reachable before it restores the previous rule set. Zero takes the host's own window.",
};

const zoneField: OperationField = {
  name: "zone",
  label: "Zone",
  kind: "text",
  placeholder: "public",
  hint: "The firewalld zone the change lands in. Hosts running plain nftables or ufw do not have zones and refuse the operation.",
};

const enableField: OperationField = {
  name: "enable",
  label: "Open it",
  kind: "boolean",
  hint: "On adds the entry to the zone, off takes it away.",
};

function zoneCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "zone", "Name the zone this acts on.")) {
    shaped(problems, form, "zone", FIREWALL_ZONE,
      "A zone name is letters, digits, underscore and hyphen, up to 17 characters.");
  }
  return problems;
}

export const security: OperationEntry[] = [
  define({
    action: "firewall.rule.ensure",
    title: "Put a firewall rule in place",
    group: GROUP,
    key: "firewall",
    plan: FIREWALL_PLAN,
    note: "The rule is built out of fields rather than typed as firewall text: a rule written as text is a language, and the host would run everything that can be written in it.",
    fields: [
      {
        name: "rule_id", label: "Rule", kind: "text", placeholder: "allow-monitoring",
        hint: "How the panel recognises this rule on every host; ordering it again changes the same rule rather than adding a second one.",
      },
      {
        name: "chain", label: "Direction", kind: "select",
        options: [
          { value: "input", label: "Traffic coming in" },
          { value: "output", label: "Traffic going out" },
        ],
      },
      {
        name: "action", label: "What happens to it", kind: "select",
        options: [
          { value: "accept", label: "Let it through" },
          { value: "drop", label: "Drop it silently" },
          { value: "reject", label: "Refuse it and say so" },
        ],
      },
      {
        name: "protocol", label: "Protocol", kind: "select",
        options: [
          { value: "", label: "Any" },
          { value: "tcp", label: "TCP" },
          { value: "udp", label: "UDP" },
          { value: "icmp", label: "ICMP" },
        ],
      },
      {
        name: "ports", label: "Ports", kind: "list", placeholder: "9100",
        hint: "One per line, each a number or a range such as 9100-9200. Only for TCP and UDP.",
      },
      {
        name: "sources", label: "From these addresses", kind: "list", placeholder: "192.0.2.0/24",
        hint: "One per line, each with its mask, taken from your own addressing - the example is a documentation range and matches nothing. Empty means from anywhere.",
      },
      { name: "interface", label: "On this interface", kind: "text", hint: "Empty means every interface." },
      { name: "comment", label: "Comment", kind: "text", hint: "Why the rule exists; it is written next to it on the host.", wide: true },
      breakGlassField,
      rollbackField,
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "rule_id", "Give the rule a name.")) {
        shaped(problems, form, "rule_id", FIREWALL_RULE,
          "A rule name is lower-case letters, digits and hyphens.");
      }
      const chain = text(form, "chain");
      if (chain !== "input" && chain !== "output") {
        problems.push({ field: "chain", message: "Say whether the rule is about traffic coming in or going out." });
      }
      const action = text(form, "action");
      if (!["accept", "drop", "reject"].includes(action)) {
        problems.push({ field: "action", message: "Say what happens to the traffic the rule matches." });
      }
      const protocol = text(form, "protocol");
      const ports = list(form, "ports");
      if (ports.length > 0 && protocol !== "tcp" && protocol !== "udp") {
        problems.push({ field: "ports", message: "Ports belong to TCP and UDP; pick one of them or leave the ports out." });
      }
      const badPort = ports.find((port) => !portValid(port));
      if (badPort !== undefined) {
        problems.push({ field: "ports", message: "{value} is neither a port nor a range inside 1-65535.", params: { value: badPort } });
      }
      const sources = list(form, "sources");
      const badSource = sources.find((source) => !cidrValid(source));
      if (badSource !== undefined) {
        problems.push({ field: "sources", message: "{value} is not an address with a mask, e.g. 192.0.2.0/24.", params: { value: badSource } });
      }
      shaped(problems, form, "interface", INTERFACE_NAME, "An interface name is letters, digits and . _ - .");
      if (/["\\\n]/.test(text(form, "comment"))) {
        problems.push({ field: "comment", message: "The comment carries no quote, backslash or newline." });
      }
      if (protocol === "" && ports.length === 0 && sources.length === 0 && text(form, "interface") === "") {
        problems.push({
          message: "A rule that matches nothing in particular covers all traffic. Narrow it, or make that a decision of its own.",
        });
      }
      return problems;
    },
    target: (form) => text(form, "rule_id"),
  }),

  define({
    action: "firewall.rule.remove",
    title: "Take a firewall rule away",
    group: GROUP,
    key: "firewall",
    plan: FIREWALL_PLAN,
    fields: [
      { name: "rule_id", label: "Rule", kind: "text", hint: "The name the panel keeps the rule under." },
      breakGlassField,
      rollbackField,
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "rule_id", "Name the rule to take away.")) {
        shaped(problems, form, "rule_id", FIREWALL_RULE, "A rule name is lower-case letters, digits and hyphens.");
      }
      return problems;
    },
    target: (form) => text(form, "rule_id"),
  }),

  define({
    action: "firewall.zone.port",
    title: "Open or close a port in a firewalld zone",
    group: GROUP,
    key: "firewall",
    plan: FIREWALL_PLAN,
    fields: [
      zoneField,
      {
        name: "ports", label: "Port", kind: "list", placeholder: "8443",
        hint: "One port or range; this operation is about a single entry, so a longer list is refused.",
      },
      {
        name: "protocol", label: "Protocol", kind: "select",
        options: [{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }],
      },
      enableField,
      breakGlassField,
    ],
    check: (form) => {
      const problems = zoneCheck(form);
      const ports = list(form, "ports");
      if (ports.length !== 1) {
        problems.push({ field: "ports", message: "Name exactly one port or range; the zone takes one entry at a time." });
      } else if (!portValid(ports[0])) {
        problems.push({ field: "ports", message: "{value} is neither a port nor a range inside 1-65535.", params: { value: ports[0] } });
      }
      const protocol = text(form, "protocol");
      if (protocol !== "tcp" && protocol !== "udp") {
        problems.push({ field: "protocol", message: "A port entry is about TCP or UDP." });
      }
      return problems;
    },
    target: (form) => `${text(form, "zone")} ${list(form, "ports").join("")}`.trim(),
  }),

  define({
    action: "firewall.zone.service",
    title: "Allow or stop a service in a firewalld zone",
    group: GROUP,
    key: "firewall",
    plan: FIREWALL_PLAN,
    fields: [
      zoneField,
      {
        name: "service", label: "Service", kind: "text", placeholder: "https",
        hint: "The service as firewalld names it; it stands for the ports that service uses.",
      },
      enableField,
      breakGlassField,
    ],
    check: (form) => {
      const problems = zoneCheck(form);
      if (required(problems, form, "service", "Name the service.")) {
        shaped(problems, form, "service", FIREWALL_SERVICE,
          "A service name is lower-case letters, digits and . _ - .");
      }
      return problems;
    },
    target: (form) => `${text(form, "zone")} ${text(form, "service")}`.trim(),
  }),

  define({
    action: "firewall.ruleset.restore",
    title: "Put a firewall rule set back",
    group: GROUP,
    key: "firewall",
    note: "The set is the one the host kept under an identifier it minted at the time of the change; it is different on every host and gone once the change was confirmed.",
    fields: [
      { name: "rollback_id", label: "Rule set", kind: "text", hint: "The identifier the host reported when it made the change." },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      required(problems, form, "rollback_id", "Name the rule set the host is to go back to.");
      return problems;
    },
    target: (form) => text(form, "rollback_id"),
  }),

  define({
    action: "ssh.config.apply",
    title: "Change the SSH server's settings",
    group: GROUP,
    key: "ssh",
    plan: "Every host computes its own difference first: the planning step shows what the server applies now against what is ordered, together with the panel's own file the write replaces in full.",
    note: "A field left empty is a setting the panel does not touch: this changes what it is told to change and nothing else.",
    fields: [
      { name: "port", label: "Port", kind: "text", placeholder: "22", hint: "Empty leaves the port where it is. Remember the firewall follows separately." },
      {
        name: "permit_root_login", label: "Root may log in", kind: "select",
        options: [
          { value: "", label: "Leave as it is" },
          { value: "no", label: "No" },
          { value: "prohibit-password", label: "By key only" },
          { value: "forced-commands-only", label: "For forced commands only" },
          { value: "yes", label: "Yes" },
        ],
      },
      {
        name: "password_authentication", label: "Passwords accepted", kind: "select",
        options: [
          { value: "", label: "Leave as it is" },
          { value: "no", label: "No" },
          { value: "yes", label: "Yes" },
        ],
      },
      {
        name: "pubkey_authentication", label: "Keys accepted", kind: "select",
        options: [
          { value: "", label: "Leave as it is" },
          { value: "yes", label: "Yes" },
          { value: "no", label: "No" },
        ],
      },
      {
        name: "kbd_interactive_authentication", label: "Keyboard-interactive accepted", kind: "select",
        options: [
          { value: "", label: "Leave as it is" },
          { value: "no", label: "No" },
          { value: "yes", label: "Yes" },
        ],
      },
      { name: "max_auth_tries", label: "Attempts per connection", kind: "text", placeholder: "4", hint: "Between 1 and 100; empty leaves it as it is." },
      { name: "allow_users", label: "Only these accounts may log in", kind: "list", hint: "One per line; empty leaves the list as it is." },
      { name: "allow_groups", label: "Only these groups may log in", kind: "list", hint: "One per line; empty leaves the list as it is." },
      { name: "deny_users", label: "These accounts may not log in", kind: "list", hint: "One per line." },
      {
        name: "allow_lockout", label: "Allow it to leave no way of logging in", kind: "boolean",
        hint: "Without it a change that turns off every authentication method is refused. A server nobody can log into is not secured, it is unavailable.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      const port = text(form, "port");
      if (port !== "" && !(/^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) {
        problems.push({ field: "port", message: "The port lies between 1 and 65535." });
      }
      const tries = text(form, "max_auth_tries");
      if (tries !== "" && !(/^\d{1,3}$/.test(tries) && Number(tries) >= 1 && Number(tries) <= 100)) {
        problems.push({ field: "max_auth_tries", message: "The number of attempts lies between 1 and 100." });
      }
      for (const field of ["allow_users", "allow_groups", "deny_users"]) {
        each(problems, list(form, field), field, SSH_ACCOUNT,
          "{value} is not an account pattern the server would take.");
      }
      return problems;
    },
    target: () => "sshd",
  }),

  define({
    action: "selinux.mode.set",
    title: "Switch SELinux between enforcing and permissive",
    group: GROUP,
    key: "security",
    note: "The panel does not turn SELinux off: coming back from that needs the whole filesystem relabelled and a reboot, which is not something the panel can promise.",
    fields: [
      {
        name: "mode", label: "Mode", kind: "select",
        options: [
          { value: "enforcing", label: "Enforcing - the policy is applied" },
          { value: "permissive", label: "Permissive - violations are only recorded" },
        ],
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      const mode = text(form, "mode");
      if (mode !== "enforcing" && mode !== "permissive") {
        problems.push({ field: "mode", message: "Pick enforcing or permissive." });
      }
      return problems;
    },
    target: (form) => text(form, "mode"),
  }),

  define({
    action: "security.remediate",
    title: "Fix compliance findings across the fleet",
    group: GROUP,
    key: "security",
    note: "Ordered from the security view, where every host's steps are computed from its own findings. There is no fix-all: an empty list is not everything.",
    fields: [
      {
        name: "check_ids", label: "Checks to fix", kind: "list", wide: true,
        hint: "One check identifier per line, as the compliance view names them.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      const checks = list(form, "check_ids");
      if (checks.length === 0) {
        problems.push({ field: "check_ids", message: "Name the checks to fix; there is no fix-all." });
      }
      const seen = new Set<string>();
      const repeated = checks.find((id) => (seen.has(id) ? true : (seen.add(id), false)));
      if (repeated !== undefined) {
        problems.push({ field: "check_ids", message: "The check {value} is named twice.", params: { value: repeated } });
      }
      return problems;
    },
    target: (form) => list(form, "check_ids").join(", "),
  }),
];
