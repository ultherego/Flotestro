import { registryOrder, type RegistryOrder } from "./module";

/* Every unit operation this page places goes through the operation
   registry, so the host page and the Bulk workspace send one payload and
   refuse one set of names - a unit reached through the address bar with a
   suffix systemd does not know among them. */

/** Starting, stopping, restarting or clearing the failed state of one unit. */
export function unitOrder(action: string, unit: string): RegistryOrder {
  return registryOrder(action, { unit });
}

/** Deciding whether a unit starts at boot, or whether it may start at all. */
export function unitToggleOrder(action: string, unit: string, enabled: boolean): RegistryOrder {
  return registryOrder(action, { unit, enabled });
}
