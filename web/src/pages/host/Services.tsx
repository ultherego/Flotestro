import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Foot, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Summary, Table, Widgets, countWhere,
  useHost, useModule,
} from "./shared";
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

  const allUnits = listing.data?.payload?.units ?? [];
  const units = allUnits.filter((unit) => {
    if (activeOnly && unit.active_state !== "active") return false;
    if (!filter) return true;
    return unit.name.toLowerCase().includes(filter.toLowerCase());
  });
  // The state counts come from the full listing, which exists only after a
  // read; the failed count comes from the inventory and is known earlier.
  // Neither is zero before it is known.
  const listed = listing.data ? allUnits : undefined;
  const failedCount = known ? failed.length : countWhere(listed, (unit) => unit.active_state === "failed");
  const bootStates = ["enabled", "disabled", "static", "masked"];

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Services")}
        description={t("systemd units: what failed, what runs and what starts at boot.")}
        actions={
          <button
            onClick={() => request.mutate({ action: "unit.status", payload: { unit_status: { all: true } } })}
            disabled={request.isPending || host.connection_state !== "online"}
          >
            {request.isPending ? t("Requesting…") : t("Read from host")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      <Widgets>
      {/* An unread state must not look like no failed units: the bar shows
          dashes until the host has been read. */}
      <Summary
        title={t("Unit states")}
        description={t("Every unit the host lists, by its active state.")}
        span={12}
        segments={[
          { label: t("active"), value: countWhere(listed, (unit) => unit.active_state === "active"), tone: "ok" },
          { label: t("failed"), value: failedCount, tone: "error" },
          { label: t("inactive"), value: countWhere(listed, (unit) => unit.active_state === "inactive"), tone: "neutral" },
          { label: t("other"), value: countWhere(listed, (unit) => !["active", "failed", "inactive"].includes(unit.active_state)), tone: "unknown" },
        ]}
      />

      {/* The failed units stand beside the full list: they are the reason
          to open the page, and the list is where the rest is found. Under
          them, what starts at boot. */}
      <Section title={t("Failed units")} count={known ? failed.length : undefined} span={4} flush>
        {!known ? (
          <Empty>{t("Unit states could not be determined.")}</Empty>
        ) : failed.length === 0 ? (
          <Empty>{t("No unit is in a failed state.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Unit")}</th><th>{t("Actions")}</th></tr></thead>
            <tbody>
              {failed.map((unit) => (
                <tr key={unit}>
                  <td className="hm-mono">{unit}</td>
                  <td>
                    <div className="operations">
                      <button onClick={() => operation("unit.restart", unit)}>{t("Restart")}</button>
                      <button onClick={() => operation("unit.start", unit)}>{t("Start")}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <div className="hm-section-body">
          <p className="widget-subhead">{t("On boot")}</p>
          {listed ? (
            <Breakdown
              items={[
                ...bootStates.map((state) => ({
                  label: state, value: countWhere(listed, (unit) => unit.unit_file_state === state) ?? 0,
                  tone: state === "masked" ? "warn" as const : state === "enabled" ? "ok" as const : "info" as const,
                })),
                { label: t("other"), value: countWhere(listed, (unit) => !bootStates.includes(unit.unit_file_state ?? "")) ?? 0, tone: "info" as const },
              ]}
            />
          ) : (
            <p className="source" style={{ margin: 0 }}>{t("Known after a read from the host.")}</p>
          )}
        </div>
      </Section>

      <Section
        title={t("All units")}
        count={listing.data ? units.length : undefined}
        span={8}
        description={t("The full list is read from the host on request, not on every inventory cycle.")}
        tools={listing.data && (
          <>
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
          </>
        )}
        flush
      >
        {!listing.data ? (
          <Empty>{t("This host has not been read yet. Use “Read from host”.")}</Empty>
        ) : (
          <>
            {/* A cut-off listing is marked: a list without that mark would
                look complete. */}
            {listing.data.payload?.truncated && (
              <p className="warning">
                <span>{t("The list was truncated by the host limit; narrow the filter on the host.")}</span>
              </p>
            )}
            <Table>
              <thead>
                <tr>
                  <th>{t("Unit")}</th><th>{t("Active")}</th><th>{t("Sub")}</th><th>{t("On boot")}</th><th>{t("Actions")}</th>
                </tr>
              </thead>
              <tbody>
                {units.map((unit) => (
                  <tr key={unit.name}>
                    <td className="hm-mono">{unit.name}</td>
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
                          <button className="hm-danger" onClick={() => setToMask(unit)}>{t("Mask")}</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Foot>
              <span>
                {t("{shown} of {total} units shown · read", { shown: units.length, total: allUnits.length })}{" "}
                <Time value={listing.data.observed_at} />
              </span>
            </Foot>
          </>
        )}
      </Section>
      </Widgets>

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
    </ModulePage>
  );
}
