import type { ComponentType } from "react";
import type { Host } from "../../../lib/types";
import { Overview } from "./Overview";
import { System } from "./System";
import { Packages } from "./Packages";
import { Services } from "./Services";
import { Processes } from "./Processes";
import { Schedules } from "./Schedules";
import { Kernel } from "./Kernel";
import { Time } from "./Time";
import { Power } from "./Power";
import { Policies } from "./Policies";
import { Network } from "./Network";
import { Resolver } from "./Resolver";
import { Firewall } from "./Firewall";
import { SshServer } from "./SshServer";
import { Storage } from "./Storage";
import { Files } from "./Files";
import { Backups } from "./Backups";
import { Containers } from "./Containers";
import { Compose } from "./Compose";
import { Security } from "./Security";
import { Vulnerabilities } from "./Vulnerabilities";
import { Certificates } from "./Certificates";
import { Accounts } from "./Accounts";
import { Identity } from "./Identity";
import { Logs } from "./Logs";
import { Monitoring } from "./Monitoring";
import { Jobs } from "./Jobs";
import { Audit } from "./Audit";

/**
 * Which module of a host is drawn by what.
 *
 * The registry of modules themselves - what a host has, what each needs
 * of it, which heading it sits under - is lib/modules and is shared with
 * the panel being replaced. This is only the other half: the component
 * that draws each one here. A segment with nothing against it says it has
 * not been rewritten yet and offers the screen as it stands, so the rail
 * can list every module from the first day.
 *
 * Every segment the registry names now has one. The test beside this file
 * holds the two lists to each other, so a module added to the registry
 * without a screen is a failure here rather than a blank page later.
 */
export type HostModule = ComponentType<{ host: Host }>;

export const HOST_MODULES: Record<string, HostModule> = {
  overview: Overview,
  system: System,
  packages: Packages,
  services: Services,
  processes: Processes,
  schedules: Schedules,
  kernel: Kernel,
  time: Time,
  power: Power,
  policies: Policies,
  network: Network,
  dns: Resolver,
  firewall: Firewall,
  ssh: SshServer,
  storage: Storage,
  files: Files,
  backups: Backups,
  containers: Containers,
  compose: Compose,
  security: Security,
  vulnerabilities: Vulnerabilities,
  certificates: Certificates,
  accounts: Accounts,
  identity: Identity,
  logs: Logs,
  monitoring: Monitoring,
  jobs: Jobs,
  audit: Audit,
};
