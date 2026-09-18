import {
  addressValid, bounded, define, each, formOf, INTERFACE_NAME, list, payloadOf, prefixedAddressValid,
  required, shaped, text,
  type FormProblem, type FormValue, type OperationEntry, type OperationField,
} from "./fields";

/**
 * The network and the resolver.
 *
 * Every change here describes the target state of an interface, never the
 * commands to reach it, and every one of them can cut the host off. That is
 * why the host holds the change open for a while and puts the old profile
 * back when nobody confirms it is still reachable.
 */

const GROUP = "Network";

const PLAN_NOTE =
  "Every host computes its own difference first: the planning step shows the profile it has now against the one ordered, and the change is bound to that. A profile changed in the meantime stops the change.";

const interfaceField: OperationField = {
  name: "interface",
  label: "Interface",
  kind: "text",
  hint: "The name the host knows the link by, e.g. eth0 or ens192. The panel finds the profile behind it itself.",
  placeholder: "eth0",
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
        name: "addresses", label: "Addresses", kind: "list", wide: true, placeholder: "10.0.0.5/24",
        hint: "One per line, each with its prefix. Required when the address is typed in: an interface left without one is a host nobody reaches.",
      },
      { name: "gateway", label: "Gateway", kind: "text", placeholder: "10.0.0.1" },
      { name: "dns", label: "Name servers", kind: "list", hint: "One address per line; empty leaves the resolver as it is." },
      rollbackField,
    ],
    check: (form) => {
      const problems = interfaceCheck(form);
      const method = text(form, "method");
      if (method !== "auto" && method !== "manual") {
        problems.push({ field: "method", message: "Say where the address comes from: from the network or typed in here." });
      }
      const addresses = list(form, "addresses");
      if (method === "manual" && addresses.length === 0) {
        problems.push({ field: "addresses", message: "An address typed in by hand is the one thing this change cannot do without." });
      }
      const badAddress = addresses.find((address) => !prefixedAddressValid(address));
      if (badAddress !== undefined) {
        problems.push({ field: "addresses", message: "{value} is not an address with a prefix, e.g. 10.0.0.5/24.", params: { value: badAddress } });
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
        placeholder: "192.168.20.0/24 via 10.0.0.1",
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
        name: "servers", label: "Name servers", kind: "list", wide: true, placeholder: "10.0.0.53",
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
