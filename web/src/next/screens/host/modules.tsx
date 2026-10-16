import type { ComponentType } from "react";
import type { Host } from "../../../lib/types";
import { Overview } from "./Overview";

/**
 * Which module of a host is drawn by what.
 *
 * The registry of modules themselves - what a host has, what each needs
 * of it, which heading it sits under - is lib/modules and is shared with
 * the panel being replaced. This is only the other half: the component
 * that draws each one here. A segment with nothing against it says it has
 * not been rewritten yet and offers the screen as it stands, so the rail
 * can list every module from the first day.
 */
export type HostModule = ComponentType<{ host: Host }>;

export const HOST_MODULES: Record<string, HostModule> = {
  overview: Overview,
};
