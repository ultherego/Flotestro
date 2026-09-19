import {
  addressValid, bounded, count, define, each, formOf, INTERFACE_NAME, list, payloadOf,
  prefixedAddressValid, required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * The network and the resolver.
 */

const GROUP = "Network";

const PLAN_NOTE =
  "Every host computes its own difference first: the planning step shows the profile it has now against the one ordered, and the change is bound to that. A profile changed in the meantime stops the change.";

const interfaceField: OperationField = {
  name: "interface",
  label: "Interface",
  kind: "text",
  // No example name here on purpose: an interface is called whatever the
  // host calls it - enp2s0, ens192, eno1np0 - and a name borrowed from an
  // example is a name the host does not have.
  hint: "The name the host itself reports for the link, copied exactly; the host's network page lists them. The panel finds the profile behind it.",
};

const rollbackField: OperationField = {
  name: "rollback_seconds",
  label: "Put it back after",
  kind: "duration",
  min: 0,
  max: 3600,
  hint: "How long the host waits for the panel to confirm it is still reachable before it puts the old profile back. Zero takes the host's own window - it is never \"no rollback\".",
};

function interfaceCheck(form: FormValue): FormProblem[] {
  const problems: FormProblem[] = [];
  if (required(problems, form, "interface", "Name the interface this acts on.")) {
    shaped(problems, form, "interface", INTERFACE_NAME,
      "An interface name is letters, digits and . _ - , up to 15 characters.");
  }
  bounded(problems, form, "rollback_seconds", 1, 3600, "The rollback window lies between 1 and 3600 seconds.");
  return problems;
}

/** The fields of a route change beside the list itself. */
const routeBase: OperationField[] = [interfaceField, rollbackField];

/** Whether a value is an IPv6 address; an IPv4 one in an IPv6 field is a mistake, not a shorthand. */
function sixthAddressValid(value: string): boolean {
  return value.includes(":") && addressValid(value);
}

/** Whether a value is an IPv6 address with its prefix length. */
function sixthPrefixedValid(value: string): boolean {
  const slash = value.lastIndexOf("/");
  if (slash < 0) return false;
  return sixthAddressValid(value.slice(0, slash)) && /^\d{1,3}$/.test(value.slice(slash + 1));
}

/**
 * The second family of an address profile.
 */
const ipv6Fields: OperationField[] = [
  {
    name: "method6", label: "Where the IPv6 address comes from", kind: "select",
    options: [
      { value: "", label: "Leave it as the host has it" },
      { value: "auto", label: "From the network (router or DHCPv6)" },
      { value: "manual", label: "Typed in here" },
      { value: "disabled", label: "No IPv6 on this interface" },
    ],
    hint: "Left alone, the second family keeps whatever the host has. It is asked separately from IPv4 because the two are separate decisions.",
  },
  {
    name: "addresses6", label: "IPv6 addresses", kind: "list", wide: true, placeholder: "2001:db8::5/64",
    hint: "One per line, each with its prefix length. Required when the IPv6 address is typed in.",
  },
  {
    name: "gateway6", label: "IPv6 gateway", kind: "text", placeholder: "fe80::1",
    hint: "May be a link-local address (fe80::…): that is how an IPv6 router ordinarily announces itself.",
  },
  {
    name: "accept_ra", label: "Router advertisements", kind: "select",
    options: [
      { value: "", label: "Leave it as the host has it" },
      { value: "off", label: "Ignore them" },
      { value: "on", label: "Accept them" },
      { value: "on-forwarding", label: "Accept them even while forwarding" },
    ],
    hint: "Whether the host listens to the routers on its segment. A mechanism that has no switch for it refuses the setting rather than guessing.",
  },
  {
    name: "privacy", label: "Privacy extensions", kind: "select",
    options: [
      { value: "", label: "Leave it as the host has it" },
      { value: "off", label: "Off" },
      { value: "prefer-public", label: "Temporary addresses, public preferred" },
      { value: "prefer-temporary", label: "Temporary addresses preferred" },
    ],
    hint: "Temporary source addresses for outgoing connections. netplan has one switch only and refuses the middle setting by name.",
  },
];

/** The IPv6 part of the checks: shapes only; whether the host has the family at all is the plan's answer. */
function ipv6Check(problems: FormProblem[], form: FormValue): void {
  const method = text(form, "method6");
  const addresses = list(form, "addresses6");
  if (method === "manual" && addresses.length === 0) {
    problems.push({ field: "addresses6", message: "An IPv6 address typed in by hand is the one thing this change cannot do without." });
  }
  const bad = addresses.find((address) => !sixthPrefixedValid(address));
  if (bad !== undefined) {
    problems.push({ field: "addresses6", message: "{value} is not an IPv6 address with a prefix length, e.g. 2001:db8::5/64.", params: { value: bad } });
  }
  const gateway = text(form, "gateway6");
  if (gateway !== "" && !sixthAddressValid(gateway)) {
    problems.push({ field: "gateway6", message: "The IPv6 gateway is one IPv6 address; a link-local one (fe80::…) is the normal case." });
  }
}

/** The kinds of layer the panel builds, in the kernel's own words. */
const LAYER_KINDS = ["bond", "bridge", "vlan"];

/** The bond modes the kernel knows, spelled as it spells them. */
const BOND_MODES = ["balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"];

const layerFields: OperationField[] = [
  {
    name: "name", label: "Name", kind: "text",
    hint: "The name the layer will carry on the host. A name the host already uses for something else is refused rather than taken over.",
  },
  {
    name: "kind", label: "Kind", kind: "select",
    options: [
      { value: "bond", label: "Bond (several links carrying one address)" },
      { value: "bridge", label: "Bridge (several links on one segment)" },
      { value: "vlan", label: "VLAN (tagged traffic on one link)" },
    ],
    hint: "What the layer is. A bond joins links for redundancy, a bridge puts them on one segment, a VLAN rides tagged on one of them.",
  },
  {
    name: "members", label: "Members", kind: "list", wide: true,
    hint: "One interface per line, named as the host reports them, for a bond or a bridge. A VLAN has no members: it names its parent instead. An interface another layer already owns is refused.",
  },
  {
    name: "mode", label: "Bond mode", kind: "select",
    options: [
      { value: "active-backup", label: "active-backup (one link carries, the rest wait)" },
      { value: "802.3ad", label: "802.3ad (LACP, agreed with the switch)" },
      { value: "balance-rr", label: "balance-rr" },
      { value: "balance-xor", label: "balance-xor" },
      { value: "broadcast", label: "broadcast" },
      { value: "balance-tlb", label: "balance-tlb" },
      { value: "balance-alb", label: "balance-alb" },
    ],
    default: "active-backup",
    hint: "How the bond spreads traffic. 802.3ad needs the switch configured to match; active-backup needs nothing from it.",
  },
  {
    name: "miimon_ms", label: "Link monitoring (ms)", kind: "number", min: 0, max: 60000, default: 100,
    hint: "How often the bond checks its members, in milliseconds. Zero switches the monitoring off, and a bond that does not watch its members keeps sending into a dead one.",
  },
  {
    name: "primary", label: "Primary member", kind: "text",
    hint: "The member that carries the traffic while it is up. It has to be one of the members above.",
  },
  {
    name: "lacp_rate", label: "LACP rate", kind: "select",
    options: [
      { value: "", label: "The driver's own" },
      { value: "slow", label: "slow (every 30 s)" },
      { value: "fast", label: "fast (every second)" },
    ],
    hint: "Only for 802.3ad. On any other mode it is refused rather than ignored.",
  },
  {
    name: "stp", label: "Spanning tree on the bridge", kind: "boolean",
    hint: "Keeps a loop between switches from flooding the segment, at the cost of a delay before a port forwards.",
  },
  {
    name: "vlan_filtering", label: "VLAN filtering on the bridge", kind: "boolean",
    hint: "Separates VLANs inside the bridge. Neither nmstate nor netplan writes it through this panel, so it is refused by name rather than dropped.",
  },
  {
    name: "parent", label: "VLAN parent", kind: "text",
    hint: "The interface the tagged traffic runs on, named as the host reports it. A parent the host does not report is refused before anything is written.",
  },
  {
    name: "vlan_id", label: "VLAN identifier", kind: "number", min: 1, max: 4094,
    hint: "The tag, between 1 and 4094. Zero means no VLAN and 4095 is reserved, so neither is one a host carries traffic on.",
  },
  {
    name: "protocol", label: "VLAN protocol", kind: "select",
    options: [
      { value: "", label: "802.1Q (the usual one)" },
      { value: "802.1Q", label: "802.1Q" },
      { value: "802.1ad", label: "802.1ad (the outer tag of a stacked VLAN)" },
    ],
  },
  {
    name: "mtu", label: "MTU", kind: "text", placeholder: "1500",
    hint: "The largest frame the layer carries, or auto. Written as text because auto is a value here.",
  },
];

export const network: OperationEntry[] = [
  define({
    action: "network.profile.apply",
    title: "Set an interface's addressing",
    group: GROUP,
    key: "network",
    plan: PLAN_NOTE,
    fields: [
      interfaceField,
      {
        name: "method", label: "Where the address comes from", kind: "select",
        options: [
          { value: "auto", label: "From the network (DHCP)" },
          { value: "manual", label: "Typed in here" },
        ],
        hint: "Automatic takes the address the network hands out; typed in means the addresses below and nothing else.",
      },
      {
        name: "addresses", label: "Addresses", kind: "list", wide: true, placeholder: "192.0.2.5/24",
        hint: "One per line, each with its prefix. Required when the address is typed in: an interface left without one is a host nobody reaches.",
      },
      { name: "gateway", label: "Gateway", kind: "text", placeholder: "192.0.2.1" },
      { name: "dns", label: "Name servers", kind: "list", hint: "One address per line; empty leaves the resolver as it is." },
      ...ipv6Fields,
      rollbackField,
    ],
    check: (form) => {
      const problems = interfaceCheck(form);
      const method = text(form, "method");
      // One family is enough to order: the other keeps what the host has.
      if (method !== "" && method !== "auto" && method !== "manual") {
        problems.push({ field: "method", message: "Say where the address comes from: from the network or typed in here." });
      }
      if (method === "" && text(form, "method6") === "" && text(form, "accept_ra") === "" && text(form, "privacy") === "") {
        problems.push({ field: "method", message: "Say what is to change for at least one address family." });
      }
      ipv6Check(problems, form);
      const addresses = list(form, "addresses");
      if (method === "manual" && addresses.length === 0) {
        problems.push({ field: "addresses", message: "An address typed in by hand is the one thing this change cannot do without." });
      }
      const badAddress = addresses.find((address) => !prefixedAddressValid(address));
      if (badAddress !== undefined) {
        problems.push({ field: "addresses", message: "{value} is not an address with a prefix, e.g. 192.0.2.5/24.", params: { value: badAddress } });
      }
      const gateway = text(form, "gateway");
      if (gateway !== "" && !addressValid(gateway)) {
        problems.push({ field: "gateway", message: "The gateway is one IP address." });
      }
      const badServer = list(form, "dns").find((server) => !addressValid(server));
      if (badServer !== undefined) {
        problems.push({ field: "dns", message: "{value} is not an IP address.", params: { value: badServer } });
      }
      return problems;
    },
    target: (form) => text(form, "interface"),
  }),

  define({
    action: "network.route.ensure",
    title: "Set an interface's routes",
    group: GROUP,
    key: "network",
    plan: PLAN_NOTE,
    note: "The list is the profile's whole set of routes, not an addition: an empty list is a profile with no routes of its own, and it is sent as such rather than left out.",
    fields: [
      ...routeBase,
      {
        name: "routes", label: "Routes", kind: "list", wide: true,
        placeholder: "198.51.100.0/24 via 192.0.2.1",
        hint: "One per line, each as a destination with its prefix and the gateway it goes through.",
      },
    ],
    compose: (form) => ({ ...payloadOf(routeBase, form), routes: list(form, "routes") }),
    read: (section) => {
      const base = formOf(routeBase, section);
      if (!base) return null;
      const routes = section.routes;
      if (routes !== undefined && routes !== null && !Array.isArray(routes)) return null;
      if (Array.isArray(routes) && routes.some((route) => typeof route !== "string")) return null;
      return { ...base, routes: Array.isArray(routes) ? (routes as string[]).join("\n") : "" };
    },
    check: (form) => {
      const problems = interfaceCheck(form);
      const bad = list(form, "routes").find((route) => !/^[0-9A-Fa-f:.]+\/\d{1,3}( via [0-9A-Fa-f:.]+)?( dev [A-Za-z0-9._-]{1,15})?$/.test(route));
      if (bad !== undefined) {
        problems.push({ field: "routes", message: "{value} is not a route; write it as destination/prefix via gateway.", params: { value: bad } });
      }
      return problems;
    },
    target: (form) => text(form, "interface"),
  }),

  define({
    action: "network.mtu.set",
    title: "Set an interface's MTU",
    group: GROUP,
    key: "network",
    plan: PLAN_NOTE,
    fields: [
      interfaceField,
      {
        name: "mtu", label: "MTU", kind: "text", placeholder: "1500",
        hint: "The largest frame the link carries, or auto to leave it to the network. It is written as text because auto is a value here.",
      },
      rollbackField,
    ],
    check: (form) => {
      const problems = interfaceCheck(form);
      const mtu = text(form, "mtu");
      if (mtu === "") {
        problems.push({ field: "mtu", message: "Say what the MTU is to be." });
      } else if (mtu !== "auto" && !(/^\d{2,5}$/.test(mtu) && Number(mtu) >= 68 && Number(mtu) <= 65535)) {
        problems.push({ field: "mtu", message: "The MTU is a number between 68 and 65535, or auto." });
      }
      return problems;
    },
    target: (form) => text(form, "interface"),
  }),

  define({
    action: "network.link.apply",
    title: "Build or change a bond, a bridge or a VLAN",
    group: GROUP,
    key: "network",
    plan: PLAN_NOTE,
    note: "The layering says what an interface is made of, not what it carries. Enslaving a link moves its address to the layer above, so the host refuses a member another layer already owns, a bond of one member, a VLAN on a parent it does not have, and any layer that would swallow the interface the panel talks over. A host whose mechanism cannot express a bond says so instead of writing half of one.",
    fields: [...layerFields, rollbackField],
    // The layer travels as a description of its own inside the network
    // section, and the interface field repeats its name: the panel shows the
    // operator one name and the host writes one name.
    extra: ["interface", "link"],
    compose: (form) => {
      const payload: Record<string, unknown> = {
        interface: text(form, "name"),
        link: payloadOf(layerFields, form),
      };
      const seconds = count(form, "rollback_seconds");
      if (seconds !== 0) payload.rollback_seconds = seconds;
      return payload;
    },
    read: (section) => {
      const link = section.link;
      if (link === undefined || link === null || typeof link !== "object" || Array.isArray(link)) return null;
      const form = formOf(layerFields, link as Record<string, unknown>);
      if (!form) return null;
      const seconds = section.rollback_seconds;
      if (seconds !== undefined && seconds !== null && typeof seconds !== "number") return null;
      return { ...form, rollback_seconds: typeof seconds === "number" ? seconds : 0 };
    },
    check: (form) => {
      const problems: FormProblem[] = [];
      if (required(problems, form, "name", "Name the layer the host is to carry.")) {
        shaped(problems, form, "name", INTERFACE_NAME,
          "An interface name is letters, digits and . _ - , up to 15 characters.");
      }
      bounded(problems, form, "rollback_seconds", 1, 3600, "The rollback window lies between 1 and 3600 seconds.");
      const kind = text(form, "kind");
      if (!LAYER_KINDS.includes(kind)) {
        problems.push({ field: "kind", message: "Say what the layer is: a bond, a bridge or a VLAN." });
      }
      const members = list(form, "members");
      each(problems, members, "members", INTERFACE_NAME,
        "{value} is not an interface name.");
      if (members.includes(text(form, "name"))) {
        problems.push({ field: "members", message: "An interface cannot be a member of itself." });
      }
      if (kind === "bond") {
        // A bond of one member carries the same traffic over the same cable
        // with a driver in between, and none of the redundancy it exists
        // for.
        if (members.length < 2) {
          problems.push({ field: "members", message: "A bond carries traffic over at least two members; with one it is the same link with a driver in between." });
        }
        if (!BOND_MODES.includes(text(form, "mode"))) {
          problems.push({ field: "mode", message: "Choose one of the bond modes the kernel knows." });
        }
        const monitoring = count(form, "miimon_ms");
        if (monitoring !== 0 && (monitoring < 50 || monitoring > 60000)) {
          problems.push({ field: "miimon_ms", message: "The link monitoring interval lies between 50 and 60000 ms; zero switches it off." });
        }
        const primary = text(form, "primary");
        if (primary !== "" && !members.includes(primary)) {
          problems.push({ field: "primary", message: "The primary member has to be one of the members." });
        }
        if (text(form, "lacp_rate") !== "" && text(form, "mode") !== "802.3ad") {
          problems.push({ field: "lacp_rate", message: "The LACP rate belongs to the mode 802.3ad and to no other." });
        }
      }
      if (kind === "vlan") {
        if (members.length > 0) {
          problems.push({ field: "members", message: "A VLAN runs on one parent interface, not on a list of members." });
        }
        if (required(problems, form, "parent", "Name the interface the tagged traffic runs on.")) {
          shaped(problems, form, "parent", INTERFACE_NAME,
            "An interface name is letters, digits and . _ - , up to 15 characters.");
        }
        const id = count(form, "vlan_id");
        if (id < 1 || id > 4094) {
          problems.push({ field: "vlan_id", message: "The VLAN identifier lies between 1 and 4094." });
        }
      }
      const mtu = text(form, "mtu");
      if (mtu !== "" && mtu !== "auto" && !(/^\d{2,5}$/.test(mtu) && Number(mtu) >= 1280 && Number(mtu) <= 65536)) {
        problems.push({ field: "mtu", message: "The MTU is a number between 1280 and 65536, or auto." });
      }
      return problems;
    },
    target: (form) => text(form, "name"),
  }),

  define({
    action: "network.link.remove",
    title: "Take a bond, a bridge or a VLAN away",
    group: GROUP,
    key: "network",
    plan: PLAN_NOTE,
    note: "The members go back to carrying their own traffic and the layer's address goes with it. A layer that carries VLANs, one that is a member of another layer, and the one the panel talks over are refused rather than removed.",
    fields: [interfaceField, rollbackField],
    check: interfaceCheck,
    target: (form) => text(form, "interface"),
  }),

  define({
    action: "network.rollback",
    title: "Put a network change back",
    group: GROUP,
    key: "network",
    note: "The plan is the one the host kept under an identifier it minted from its own clock at the time of the change; it is different on every host and gone once the change was confirmed.",
    fields: [
      interfaceField,
      {
        name: "rollback_id", label: "Plan", kind: "text",
        hint: "The identifier the host reported when it made the change.",
      },
    ],
    check: (form) => {
      const problems: FormProblem[] = [];
      // The interface is not what names the plan here, so it is optional:
      // the identifier alone says which change is being undone.
      shaped(problems, form, "interface", INTERFACE_NAME,
        "An interface name is letters, digits and . _ - , up to 15 characters.");
      required(problems, form, "rollback_id", "Name the plan the host is to go back to.");
      return problems;
    },
    target: (form) => text(form, "rollback_id"),
  }),

  define({
    action: "dns.host.apply",
    title: "Set the host's name servers",
    group: GROUP,
    key: "dns",
    plan: "Every host computes its own difference first: the planning step shows the resolver it has now against the one ordered.",
    fields: [
      interfaceField,
      {
        name: "servers", label: "Name servers", kind: "list", wide: true, placeholder: "192.0.2.53",
        hint: "One IP address per line. A resolver with no server resolves nothing, and a host without name resolution loses the directory, Kerberos and logging in.",
      },
      { name: "search_domains", label: "Search domains", kind: "list", hint: "One per line; appended to a name typed without a dot." },
      {
        name: "ignore_auto_dns", label: "Ignore the servers DHCP hands out", kind: "boolean",
        hint: "Without it the panel's servers and the provider's end up in one list, and nobody knows which one answered.",
      },
      rollbackField,
    ],
    check: (form) => {
      const problems = interfaceCheck(form);
      const servers = list(form, "servers");
      if (servers.length === 0) {
        problems.push({ field: "servers", message: "Name at least one server; a resolver without one resolves nothing." });
      }
      const bad = servers.find((server) => !addressValid(server));
      if (bad !== undefined) {
        problems.push({ field: "servers", message: "{value} is not an IP address.", params: { value: bad } });
      }
      each(problems, list(form, "search_domains"), "search_domains", /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/,
        "{value} is not a domain name.");
      return problems;
    },
    target: (form) => text(form, "interface"),
  }),
];
