import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown, Meter } from "../../components/widgets";
import {
  Fact, Facts, Field, Fields, Foot, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

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

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** A module name as the host validates it: lower-case letters, digits, underscores and hyphens. */
const MODULE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * Kernel settings and modules.
 *
 * The panel does not enumerate the whole of /proc/sys: there are a few
 * thousand keys there, most of which answer no operator's question. We show
 * the profile and what the panel wrote itself; the rest can be read on
 * request.
 */
export function Kernel() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "kernel");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("");
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [moduleName, setModuleName] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its kernel settings yet.")}</Empty>;

  const modules = (snapshot?.modules ?? []).filter((entry) =>
    filter ? entry.name.toLowerCase().includes(filter.toLowerCase()) : true,
  );
  const settings = snapshot?.settings ?? [];
  // An unread kernel has nothing to count: dashes, not zeros, until then.
  const knownSettings = snapshot?.unavailable_reason ? undefined : settings;
  const knownModules = snapshot?.unavailable_reason ? undefined : snapshot?.modules ?? [];
  const pending = (setting: Setting) => !!setting.desired && setting.desired !== setting.current;
  const maxModule = Math.max(1, ...(snapshot?.modules ?? []).map((entry) => entry.size_bytes));

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Kernel")}
        description={t("A profile of settings, not all of /proc/sys — there are thousands of keys there and most answer no question anyone asks. Anything the panel wrote is listed too, with the value the kernel currently applies.")}
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Kernel settings could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <Widgets>
      {/* The settings by whether the kernel applies what was asked, then
          the kernel itself and its modules: one summary row. */}
      <Summary
        title={t("Settings")}
        description={t("The profile keys, by whether the kernel applies the desired value.")}
        span={8}
        segments={[
          { label: t("applied"), value: countWhere(knownSettings, (setting) => !pending(setting) && setting.current !== undefined), tone: "ok" },
          { label: t("not applied yet"), value: countWhere(knownSettings, pending), tone: "warn" },
          { label: t("value unknown"), value: countWhere(knownSettings, (setting) => setting.current === undefined), tone: "unknown" },
          { label: t("written by the panel"), value: countWhere(knownSettings, (setting) => setting.managed), tone: "info" },
        ]}
      />

      <Section title={t("Kernel")} span={4} flush>
        <Facts>
          <Fact label={t("Kernel")}><span className="hm-mono">{snapshot?.release || "—"}</span></Fact>
          <Fact label={t("Managed file")}><span className="hm-mono">{snapshot?.managed_path}</span></Fact>
          {/* Some settings can only be changed on the kernel command line
              and only after a reboot - that is why it is visible. */}
          <Fact label={t("Command line")} wide><span className="source hm-mono">{snapshot?.command_line || "—"}</span></Fact>
          <Fact label={t("Modules")} wide>
            {knownModules ? (
              <Breakdown
                items={[
                  { label: t("loaded"), value: knownModules.length, tone: "ok" },
                  { label: t("blocked by Flotestro"), value: (snapshot?.blacklist ?? []).length, tone: "warn" },
                ]}
              />
            ) : "—"}
          </Fact>
        </Facts>
      </Section>

      <Section title={t("Settings")} count={settings.length} span={12} flush>
        <Table>
          <thead>
            <tr><th>{t("Key")}</th><th>{t("Current")}</th><th>{t("Desired")}</th><th>{t("Owner")}</th></tr>
          </thead>
          <tbody>
            {settings.map((setting) => (
              <tr key={setting.key}>
                <td className="hm-mono hm-primary">{setting.key}</td>
                <td className="hm-mono">{setting.current ?? <span className="badge unknown">{t("unknown")}</span>}</td>
                {/* Differing values mark a setting that waits for a reboot or
                    was changed outside the panel. */}
                <td className="hm-mono">
                  {setting.desired ?? "—"}
                  {setting.desired && setting.desired !== setting.current && (
                    <span className="badge unknown"> {t("not applied yet")}</span>
                  )}
                </td>
                <td>{setting.managed ? "Flotestro" : t("kernel default or host admin")}</td>
              </tr>
            ))}
          </tbody>
        </Table>
        <div className="hm-section-body">
          <Form>
            <Fields>
              <Field label={t("Key")}>
                <input value={key} onChange={(e) => setKey(e.target.value)} placeholder={t("Key, e.g. vm.swappiness")} />
              </Field>
              <Field label={t("Value")} narrow>
                <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={t("Value")} />
              </Field>
            </Fields>
            <FormActions>
              <button
                onClick={() =>
                  setIntent({
                    action: "sysctl.ensure",
                    label: t("Set kernel setting"),
                    description: t("{key} will be set to {value} on {host}, both now and after reboot. If the kernel does not take it immediately, the result says so.", {
                      key, value, host: host.hostname,
                    }),
                    payload: { kernel: { settings: { [key]: value } } },
                  })
                }
                disabled={!key || !value}
              >
                {t("Set")}
              </button>
            </FormActions>
          </Form>
        </div>
      </Section>

      <Section
        title={t("Modules")}
        count={modules.length}
        span={12}
        tools={
          <>
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("Filter modules")} />
            <span className="source">
              {t("{loaded} loaded · {blocked} blocked", { loaded: (snapshot?.modules ?? []).length, blocked: (snapshot?.blacklist ?? []).length })}
            </span>
          </>
        }
        flush
      >
        <Table>
          <thead>
            <tr><th>{t("Module")}</th><th>{t("Size")}</th><th>{t("Used by")}</th><th>{t("State")}</th><th>{t("Actions")}</th></tr>
          </thead>
          <tbody>
            {modules.slice(0, 60).map((entry) => (
              <tr key={entry.name}>
                <td className="hm-mono hm-primary">{entry.name}</td>
                <td><Meter value={entry.size_bytes} max={maxModule} tone="info" text={bytes(entry.size_bytes)} /></td>
                <td className="hm-mono">{(entry.used_by ?? []).join(", ") || "—"}</td>
                <td>{entry.blacklisted ? <span className="badge warn">{t("blocked by Flotestro")}</span> : t("loaded")}</td>
                <td>
                  <button
                    className={entry.blacklisted ? "secondary" : "hm-danger"}
                    onClick={() =>
                      setIntent({
                        action: "kernel.module.blacklist",
                        label: entry.blacklisted ? t("Unblock module") : t("Block module"),
                        description: entry.blacklisted
                          ? t("{module} will be allowed to load again.", { module: entry.name })
                          : t("{module} will be blocked from loading. A module already loaded stays loaded until reboot, and one pulled in by the initramfs needs that rebuilt too.", { module: entry.name }),
                        payload: { kernel: { module: entry.name, blacklist: !entry.blacklisted } },
                      })
                    }
                  >
                    {entry.blacklisted ? t("Unblock") : t("Block")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
        {modules.length > 60 && (
          <Foot><span>{t("Showing 60 of {n} modules; narrow the filter to see the rest.", { n: modules.length })}</span></Foot>
        )}
        {/* Loading is the counterpart of blocking: a module the host needs
            now, without waiting for whatever would pull it in. A blocked
            module is not loaded by this - modprobe honours the blacklist
            file the panel wrote - so the form says so first. */}
        <div className="hm-section-body">
          <Form>
            <Fields>
              <Field label={t("Module to load")} help={t("The name as modprobe takes it, e.g. br_netfilter. A module blocked by the panel has to be unblocked first.")}>
                <input value={moduleName} onChange={(e) => setModuleName(e.target.value)} placeholder="br_netfilter" />
              </Field>
            </Fields>
            <FormActions>
              <button
                className="secondary"
                disabled={!MODULE_PATTERN.test(moduleName.trim()) || (snapshot?.blacklist ?? []).includes(moduleName.trim())}
                onClick={() =>
                  setIntent({
                    action: "kernel.module.load",
                    label: t("Load module"),
                    description: t("{module} will be loaded on {host} now. It stays loaded until the next reboot; whether it comes back then depends on what pulls it in.", {
                      module: moduleName.trim(), host: host.hostname,
                    }),
                    payload: { kernel: { module: moduleName.trim() } },
                  })
                }
              >
                {t("Load module")}
              </button>
            </FormActions>
          </Form>
        </div>
      </Section>
      </Widgets>

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Kernel state read")} <Time value={snapshot.observed_at} /></span>
        </p>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ action: intent.action, reason, payload: intent.payload })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}
