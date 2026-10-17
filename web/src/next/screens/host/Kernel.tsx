import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { bytes } from "../../../lib/format";
import type { Host, InventoryFragment } from "../../../lib/types";
import { operationForm, startingForm, type FormValue } from "../../../lib/operations";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Banner, Bars, Button, Card, Empty, Fact, Facts, Field, Fields, Find, Kpi, Note, Pill,
  Readout, Table, Toolbar, type Segment,
} from "../../kit";
import {
  Confirm, freshnessOf, Guard, JobLine, OperationFields, ReadOnlyNotice, orderReady, refusalOf,
  registryOrder, useOrder, type Intent, type RegistryOrder,
} from "./Power";

/**
 * Kernel settings and modules.
 *
 * A profile of settings, not all of /proc/sys - there are thousands of
 * keys there and most answer no question anybody asks. What the panel
 * wrote is listed with the value the kernel currently applies beside it,
 * because the two disagreeing is the whole reason to open this module.
 */

type Setting = {
  key: string;
  current?: string;
  desired?: string;
  source?: string;
  managed: boolean;
};

type KernelModule = {
  name: string;
  size_bytes: number;
  used_by?: string[];
  blacklisted: boolean;
};

type Snapshot = {
  release?: string;
  command_line?: string;
  settings?: Setting[];
  modules?: KernelModule[];
  blacklist?: string[];
  managed_config?: string;
  managed_path?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/* The three changes this module offers, composed through the operation
   registry: the host module and the Bulk workspace then send one payload
   and refuse one set of values, rather than each keeping its own. */

/** The settings the operator typed, as an order. */
export function sysctlOrder(form: FormValue): RegistryOrder {
  return registryOrder("sysctl.ensure", form);
}

/** Blocking a module, or giving back one the panel blocked. */
export function moduleBlockOrder(name: string, blacklisted: boolean): RegistryOrder {
  return registryOrder("kernel.module.blacklist", { module: name, blacklist: !blacklisted });
}

/** Loading a module the host needs now. */
export function moduleLoadOrder(name: string): RegistryOrder {
  return registryOrder("kernel.module.load", { module: name });
}

/** The changes this module offers; when every one is refused, it says so once. */
const KERNEL_CHANGES = ["sysctl.ensure", "kernel.module.blacklist", "kernel.module.load"];

/** How many module rows are drawn before the filter has to narrow them. */
const MODULES_SHOWN = 60;

/** Whether a key the panel asked for is not what the kernel applies. */
export function pendingSetting(setting: Setting): boolean {
  return Boolean(setting.desired) && setting.desired !== setting.current;
}

export function Kernel({ host }: { host: Host }) {
  const t = useT();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [filter, setFilter] = useState("");
  const settingsEntry = operationForm("sysctl.ensure");
  const [settingsForm, setSettingsForm] = useState<FormValue>(() => startingForm("sysctl.ensure"));
  // The advanced view writes a payload the fields cannot show; the order
  // then waits until the fields can carry it again.
  const [settingsJson, setSettingsJson] = useState("");
  const [moduleName, setModuleName] = useState("");

  const module = useQuery({
    queryKey: ["inventory", host.id, "kernel"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/kernel`),
    retry: false,
  });
  const order = useOrder(host, () => setIntent(null));

  const snapshot = module.data?.payload;
  const settings = snapshot?.settings ?? [];
  const everyModule = snapshot?.modules ?? [];
  const blacklist = snapshot?.blacklist ?? [];
  const shown = everyModule.filter((one) =>
    filter ? one.name.toLowerCase().includes(filter.toLowerCase()) : true);
  // An unread kernel has nothing to count: dashes, not noughts, until
  // then - and "not arrived yet" counts as unread, or every tile reads as
  // a nought for as long as the request is in flight.
  const read = Boolean(module.data) && !snapshot?.unavailable_reason;
  const knownSettings = read ? settings : undefined;
  const knownModules = read ? everyModule : undefined;
  const countWhere = (test: (setting: Setting) => boolean) =>
    knownSettings === undefined ? undefined : knownSettings.filter(test).length;

  const applied = countWhere((one) => Boolean(one.desired) && !pendingSetting(one) && one.current !== undefined);
  const waiting = countWhere(pendingSetting);
  const profile: Segment[] = [
    { label: t("as desired"), value: applied, tone: "ok" },
    { label: t("not applied yet"), value: waiting, tone: "warn" },
    { label: t("value unknown"), value: countWhere((one) => one.current === undefined), tone: "unknown" },
    { label: t("watched only"), value: countWhere((one) => !one.desired && one.current !== undefined), tone: "neutral" },
    { label: t("written by the panel"), value: countWhere((one) => one.managed), tone: "info" },
  ];

  const settingsRequest = sysctlOrder(settingsForm);
  const loadRequest = moduleLoadOrder(moduleName);
  const loadBlocked = blacklist.includes(moduleName.trim());

  if (!module.data && !module.isLoading) {
    return <Empty>{t("This host has not reported its kernel settings yet.")}</Empty>;
  }

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={KERNEL_CHANGES} />
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">
          {t("Kernel settings could not be read: {reason}", { reason: snapshot.unavailable_reason })}
        </Banner>
      )}
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {order.job && <JobLine job={order.job} hostID={host.id} />}

      <Board screen={KERNEL_SCREEN} catalogue={HOST_KERNEL} drawn={{
        applied: (
          <Kpi
            icon="kernel"
            label={t("Settings as desired")}
            value={applied ?? null}
            tone="ok"
            note={knownSettings ? t("of {n} in the profile", { n: knownSettings.length }) : undefined}
          />
        ),
        waiting: (
          <Kpi
            icon="kernel"
            label={t("Not applied yet")}
            value={waiting ?? null}
            tone={waiting ? "warn" : "ok"}
            note={t("asked for, and the kernel has something else")}
          />
        ),
        loaded: (
          <Kpi
            icon="server"
            label={t("Modules loaded")}
            value={knownModules === undefined ? null : knownModules.length}
            note={blacklist.length > 0 ? t("{n} blocked by the panel", { n: blacklist.length }) : undefined}
          />
        ),
        profile: (
          <Card
            title={t("Settings")}
            note={t("The profile keys, by whether the kernel applies the desired value; a key nobody set a value for is only watched.")}
          >
            <Band segments={profile} testId="kernel-profile" />
          </Card>
        ),
        kernel: (
          <Card title={t("Kernel")} foot={freshnessOf(t, module.data)}>
            <Facts>
              <Fact label={t("Kernel")}>{snapshot?.release || "—"}</Fact>
              <Fact label={t("Managed file")}>{snapshot?.managed_path || "—"}</Fact>
              <Fact label={t("Modules")}>
                {knownModules === undefined ? "—" : (
                  <Bars items={[
                    { label: t("loaded"), value: knownModules.length, tone: "ok" },
                    { label: t("blocked by Flotestro"), value: blacklist.length, tone: "warn" },
                  ]} />
                )}
              </Fact>
            </Facts>
            {/* Some settings can only be changed on the kernel command line
                and only after a reboot - that is why it is visible. */}
            <Readout
              label={t("Command line")}
              value={snapshot?.command_line || t("unknown")}
              testId="kernel-cmdline"
            />
          </Card>
        ),
        settings: (
          <Card title={t("Settings")} note={t("{n} keys in the profile.", { n: settings.length })} flush>
            <Table
              rows={settings}
              keyOf={(one) => one.key}
              loading={module.isLoading}
              empty={t("The panel watches no kernel setting on this host.")}
              testId="kernel-settings"
              columns={[
                { key: "key", head: t("Key"), tight: true, cell: (one) => one.key },
                { key: "current", head: t("Current"), tight: true, cell: (one) => (
                  one.current ?? <Pill tone="unknown">{t("unknown")}</Pill>
                ) },
                // Differing values mark a setting that waits for a reboot or
                // was changed outside the panel.
                { key: "desired", head: t("Desired"), tight: true, cell: (one) => (
                  <>
                    {one.desired ?? (
                      <Note>{t("none")}</Note>
                    )}
                    {pendingSetting(one) && <Pill tone="warn">{t("not applied yet")}</Pill>}
                  </>
                ) },
                { key: "owner", head: t("Owner"), minor: true, cell: (one) => (
                  one.managed
                    ? <Pill tone="ok">{t("panel")}</Pill>
                    : <Note>{t("kernel default or host admin")}</Note>
                ) },
              ]}
            />
          </Card>
        ),
        set: settingsEntry ? (
          <Card
            title={t("Set kernel settings")}
            note={t("The settings are written to {path} and applied now; a key that is not in the profile above joins it.", { path: snapshot?.managed_path || "/etc/sysctl.d" })}
          >
            <Guard action="sysctl.ensure" host={host.id} explain>
              {/* The fields come from the operation registry, so this form
                  and the Bulk wizard ask for the same things and refuse the
                  same values - a key outside the panel's branches among
                  them. */}
              <OperationFields
                entry={settingsEntry}
                value={settingsForm}
                onChange={setSettingsForm}
                json={settingsJson}
                onJson={setSettingsJson}
              />
              <Button
                testId="sysctl-set"
                disabled={!orderReady(settingsRequest) || settingsJson !== ""}
                title={refusalOf(t, settingsRequest)}
                onClick={() => setIntent({
                  action: "sysctl.ensure",
                  label: t("Set kernel settings"),
                  description: t("{keys} will be set on {host}, both now and after reboot. If the kernel does not take a value immediately, the result says so.", {
                    keys: settingsEntry.summary(settingsRequest.payload), host: host.hostname,
                  }),
                  payload: settingsRequest.payload,
                })}
              >
                {t("Set")}
              </Button>
            </Guard>
          </Card>
        ) : undefined,
        modules: (
          <Card
            title={t("Modules")}
            note={t("{loaded} loaded · {blocked} blocked", { loaded: everyModule.length, blocked: blacklist.length })}
            foot={shown.length > MODULES_SHOWN
              ? t("Showing 60 of {n} modules; narrow the filter to see the rest.", { n: shown.length })
              : undefined}
            flush
          >
            <Toolbar>
              <Find value={filter} onChange={setFilter} placeholder={t("Filter modules")} testId="module-filter" />
            </Toolbar>
            <Table
              rows={shown.slice(0, MODULES_SHOWN)}
              keyOf={(one) => one.name}
              loading={module.isLoading}
              empty={t("No module of this host answers that.")}
              testId="kernel-modules"
              rowTestId={(one) => `module-${one.name}`}
              columns={[
                { key: "name", head: t("Module"), tight: true, cell: (one) => one.name },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                { key: "used", head: t("Used by"), minor: true, tight: true, cell: (one) => (
                  (one.used_by ?? []).join(", ") || "—"
                ) },
                { key: "state", head: t("State"), cell: (one) => (
                  one.blacklisted
                    ? <Pill tone="warn">{t("blocked by Flotestro")}</Pill>
                    : <Pill tone="ok">{t("loaded")}</Pill>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <Guard action="kernel.module.blacklist" host={host.id}>
                    {/* The registry keeps the list of modules the panel will
                        not block; the row reads its refusal from there. */}
                    <BlockButton entry={one} t={t} onIntent={setIntent} />
                  </Guard>
                ) },
              ]}
            />
          </Card>
        ),
        load: (
          <Card
            title={t("Load a module")}
            note={t("Loading is the counterpart of blocking: a module the host needs now, without waiting for whatever would pull it in. A module the panel blocked is not loaded by this — modprobe honours the file the panel wrote.")}
          >
            <Guard action="kernel.module.load" host={host.id} explain>
              <Fields>
                <Field
                  label={t("Module to load")}
                  hint={t("The name as modprobe takes it, e.g. br_netfilter. A module blocked by the panel has to be unblocked first.")}
                  wide
                >
                  <input
                    value={moduleName}
                    onChange={(event) => setModuleName(event.target.value)}
                    placeholder="br_netfilter"
                    data-testid="module-name"
                  />
                </Field>
              </Fields>
              {loadBlocked && <Note>{t("The panel blocks {module} on this host; unblock it first.", { module: moduleName.trim() })}</Note>}
              <Button
                kind="quiet"
                testId="module-load"
                // The blocked list is what this host reports, so it stays
                // here: the registry knows the operation, not the host.
                disabled={!orderReady(loadRequest) || loadBlocked}
                title={refusalOf(t, loadRequest)}
                onClick={() => setIntent({
                  action: "kernel.module.load",
                  label: t("Load module"),
                  description: t("{module} will be loaded on {host} now. It stays loaded until the next reboot; whether it comes back then depends on what pulls it in.", {
                    module: moduleName.trim(), host: host.hostname,
                  }),
                  payload: loadRequest.payload,
                })}
              >
                {t("Load module")}
              </Button>
            </Guard>
          </Card>
        ),
      }} />

      {intent && (
        <Confirm
          key={`${intent.action}-${intent.target ?? ""}`}
          host={host}
          intent={intent}
          busy={order.request.isPending}
          onConfirm={(reason, confirmation) => order.request.mutate({
            action: intent.action,
            reason,
            target_confirmation: confirmation,
            payload: intent.payload,
          })}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}

/**
 * The block-or-unblock button of one module row. The registry composes the
 * order, so the button is disabled with the reason on a module the panel
 * refuses to block - the same refusal the Bulk workspace shows.
 */
function BlockButton({ entry, t, onIntent }: {
  entry: KernelModule;
  t: Translate;
  onIntent: (intent: Intent) => void;
}) {
  const order = moduleBlockOrder(entry.name, entry.blacklisted);
  return (
    <Button
      kind={entry.blacklisted ? "quiet" : "danger"}
      testId={`block-${entry.name}`}
      disabled={!orderReady(order)}
      title={refusalOf(t, order)}
      onClick={() => onIntent({
        action: order.action,
        label: entry.blacklisted ? t("Unblock module") : t("Block module"),
        danger: !entry.blacklisted,
        description: entry.blacklisted
          ? t("{module} will be allowed to load again.", { module: entry.name })
          : t("{module} will be blocked from loading. A module already loaded stays loaded until reboot, and one pulled in by the initramfs needs that rebuilt too.", { module: entry.name }),
        payload: order.payload,
      })}
    >
      {entry.blacklisted ? t("Unblock") : t("Block")}
    </Button>
  );
}

/** The name this module's arrangement is stored under. */
export const KERNEL_SCREEN = "next_host_kernel";

/** The containers this module can draw, and the shape each ships with. */
export const HOST_KERNEL: BoardEntry[] = [
  { key: "applied", title: "Settings as desired", width: 4, height: 2 },
  { key: "waiting", title: "Not applied yet", width: 4, height: 2 },
  { key: "loaded", title: "Modules loaded", width: 4, height: 2 },
  { key: "profile", title: "Settings", width: 7, height: 4 },
  { key: "kernel", title: "Kernel", width: 5, height: 4 },
  { key: "settings", title: "Settings", width: 7, height: 5 },
  { key: "set", title: "Set kernel settings", width: 5, height: 5 },
  { key: "modules", title: "Modules", width: 7, height: 7 },
  { key: "load", title: "Load a module", width: 5, height: 4 },
];
