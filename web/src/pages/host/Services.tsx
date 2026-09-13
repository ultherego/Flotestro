import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type ServicesState = {
  failed_units: string[] | null;
  failed_units_known: boolean;
};

type Unit = {
  name: string;
  load_state: string;
  active_state: string;
  sub_state: string;
  unit_file_state?: string;
  n_restarts?: number;
};

type UnitListing = { units?: Unit[]; truncated?: boolean };

export function Services() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<ServicesState>(host.id, "services");
  const listing = useModule<UnitListing>(host.id, "services.full");
  const [filter, setFilter] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [toMask, setToMask] = useState<Unit | null>(null);
  const [message, setMessage] = useState("");

  const failed = module.data?.payload?.failed_units ?? [];
  const known = module.data?.payload?.failed_units_known ?? false;

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setToMask(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  function operation(action: string, unit: string) {
    request.mutate({ action, payload: { unit: { unit } } });
  }

  function toggle(action: string, unit: string, value: boolean) {
    request.mutate({
      action,
      ...(action === "unit.mask.set" ? { reason: "unit masking from the panel" } : {}),
      payload: { unit_toggle: { unit, enabled: value } },
    });
  }

  const units = (listing.data?.payload?.units ?? []).filter((unit) => {
    if (activeOnly && unit.active_state !== "active") return false;
    if (!filter) return true;
    return unit.name.toLowerCase().includes(filter.toLowerCase());
  });

  return (
    <>
      <h2>{t("Failed units")}</h2>
      {/* An unread state must not look like no failed units. */}
      {!known ? (
        <Empty>{t("Unit states could not be determined.")}</Empty>
      ) : failed.length === 0 ? (
        <Empty>{t("No unit is in a failed state.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Unit")}</th><th>{t("Actions")}</th></tr></thead>
          <tbody>
            {failed.map((unit) => (
              <tr key={unit}>
                <td>{unit}</td>
                <td>
                  <div className="operations">
                    <button onClick={() => operation("unit.restart", unit)}>{t("Restart")}</button>
                    <button onClick={() => operation("unit.start", unit)}>{t("Start")}</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ModuleFreshness fragment={module.data} />

      <h2>{t("All units")}</h2>
      <p className="subtitle">
        {t("The full list is read from the host on request, not on every inventory cycle.")}{" "}
        <button
          className="secondary"
          onClick={() => request.mutate({ action: "unit.status", payload: { unit_status: { all: true } } })}
          disabled={request.isPending || host.connection_state !== "online"}
        >
          {request.isPending ? t("Requesting…") : t("Read from host")}
        </button>
      </p>

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {!listing.data ? (
        <Empty>{t("This host has not been read yet. Use “Read from host”.")}</Empty>
      ) : (
        <>
          <div className="filters">
            <input
              placeholder={t("Filter by name")}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <label className="toggle">
              <input
                type="checkbox"
                checked={activeOnly}
                onChange={(e) => setActiveOnly(e.target.checked)}
              />
              {t("active only")}
            </label>
          </div>
          {/* A cut-off listing is marked: a list without that mark would
              look complete. */}
          {listing.data.payload?.truncated && (
            <p className="warning">
              <span>{t("The list was truncated by the host limit; narrow the filter on the host.")}</span>
            </p>
          )}
          <table>
            <thead>
              <tr>
                <th>{t("Unit")}</th><th>{t("Active")}</th><th>{t("Sub")}</th><th>{t("On boot")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {units.map((unit) => (
                <tr key={unit.name}>
                  <td>{unit.name}</td>
                  <td>
                    <span className={unit.active_state === "active" ? "badge ok" : "badge"}>
                      {unit.active_state}
                    </span>
                  </td>
                  <td>{unit.sub_state}</td>
                  <td>{unit.unit_file_state || "—"}</td>
                  <td>
                    <div className="operations">
                      {unit.active_state === "active" ? (
                        <>
                          <button onClick={() => operation("unit.restart", unit.name)}>{t("Restart")}</button>
                          <button onClick={() => operation("unit.stop", unit.name)}>{t("Stop")}</button>
                        </>
                      ) : (
                        <button onClick={() => operation("unit.start", unit.name)}>{t("Start")}</button>
                      )}
                      {/* Enabling changes the host's behaviour after a
                          reboot, so it is separate from starting now. */}
                      {unit.unit_file_state === "enabled" ? (
                        <button onClick={() => toggle("unit.enable.set", unit.name, false)}>{t("Disable")}</button>
                      ) : unit.unit_file_state === "disabled" ? (
                        <button onClick={() => toggle("unit.enable.set", unit.name, true)}>{t("Enable")}</button>
                      ) : null}
                      {unit.unit_file_state === "masked" ? (
                        <button onClick={() => toggle("unit.mask.set", unit.name, false)}>{t("Unmask")}</button>
                      ) : (
                        <button onClick={() => setToMask(unit)}>{t("Mask")}</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="source" style={{ marginTop: 12 }}>
            {t("{shown} of {total} units shown · read", { shown: units.length, total: listing.data.payload?.units?.length ?? 0 })}{" "}
            <Time value={listing.data.observed_at} />
          </p>
        </>
      )}

      {toMask && (
        <TargetConfirmation
          host={host}
          label={t("Mask unit")}
          description={t("{unit} will not be startable, by the panel or by hand, and the change survives a reboot.", { unit: toMask.name })}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              action: "unit.mask.set",
              reason,
              payload: { unit_toggle: { unit: toMask.name, enabled: true } },
            })
          }
          onCancel={() => setToMask(null)}
        />
      )}
    </>
  );
}
