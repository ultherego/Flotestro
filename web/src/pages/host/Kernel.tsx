import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { ModuleFreshness, useHost, useModule } from "./shared";
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

  return (
    <>
      <p className="subtitle">
        {t("A profile of settings, not all of /proc/sys — there are thousands of keys there and most answer no question anyone asks. Anything the panel wrote is listed too, with the value the kernel currently applies.")}
      </p>

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Kernel settings could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>{t("Kernel")}</th><td>{snapshot?.release || "—"}</td></tr>
          {/* Some settings can only be changed on the kernel command line
              and only after a reboot - that is why it is visible. */}
          <tr><th>{t("Command line")}</th><td className="source">{snapshot?.command_line || "—"}</td></tr>
          <tr><th>{t("Managed file")}</th><td>{snapshot?.managed_path}</td></tr>
        </tbody>
      </table>

      <h2>{t("Settings")}</h2>
      <table>
        <thead>
          <tr><th>{t("Key")}</th><th>{t("Current")}</th><th>{t("Desired")}</th><th>{t("Owner")}</th></tr>
        </thead>
        <tbody>
          {(snapshot?.settings ?? []).map((setting) => (
            <tr key={setting.key}>
              <td>{setting.key}</td>
              <td>{setting.current ?? <span className="badge unknown">{t("unknown")}</span>}</td>
              {/* Differing values mark a setting that waits for a reboot or
                  was changed outside the panel. */}
              <td>
                {setting.desired ?? "—"}
                {setting.desired && setting.desired !== setting.current && (
                  <span className="badge unknown"> {t("not applied yet")}</span>
                )}
              </td>
              <td>{setting.managed ? "Flotestro" : t("kernel default or host admin")}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="filters">
        <input value={key} onChange={(e) => setKey(e.target.value)} placeholder={t("Key, e.g. vm.swappiness")} style={{ minWidth: 240 }} />
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={t("Value")} style={{ width: 140 }} />
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
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      <h2>{t("Modules")}</h2>
      <div className="filters">
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("Filter modules")} />
        <span className="source">
          {t("{loaded} loaded · {blocked} blocked", { loaded: (snapshot?.modules ?? []).length, blocked: (snapshot?.blacklist ?? []).length })}
        </span>
      </div>
      <table>
        <thead>
          <tr><th>{t("Module")}</th><th>{t("Size")}</th><th>{t("Used by")}</th><th>{t("State")}</th><th>{t("Actions")}</th></tr>
        </thead>
        <tbody>
          {modules.slice(0, 60).map((entry) => (
            <tr key={entry.name}>
              <td>{entry.name}</td>
              <td>{bytes(entry.size_bytes)}</td>
              <td>{(entry.used_by ?? []).join(", ") || "—"}</td>
              <td>{entry.blacklisted ? t("blocked by Flotestro") : t("loaded")}</td>
              <td>
                <button
                  className="secondary"
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
      </table>
      {modules.length > 60 && (
        <p className="source">{t("Showing 60 of {n} modules; narrow the filter to see the rest.", { n: modules.length })}</p>
      )}

      <ModuleFreshness fragment={module.data} />
      {snapshot?.observed_at && (
        <p className="source">
          {t("Kernel state read")} <Time value={snapshot.observed_at} />
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
    </>
  );
}
