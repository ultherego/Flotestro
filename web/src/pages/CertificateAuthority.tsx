import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Authority } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

/**
 * The fleet CA.
 *
 * The rotation has two phases, because a one-phase one does not work: a
 * server certificate issued by a CA the agent does not know cuts the host
 * off at the next panel restart. The screen leads through both phases and
 * shows the condition for moving between them - the number of hosts that do
 * not know the new CA yet.
 */
export function CertificateAuthority({ reportError }: { reportError: (error: ApiError | null) => void }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");

  const query = useQuery({
    queryKey: ["pki"],
    queryFn: () => api.get<{ authorities: Authority[] }>("/api/v1/pki"),
    retry: false,
    refetchInterval: 30_000,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["pki"] });
  const onError = (error: unknown) => reportError(error instanceof ApiError ? error : null);

  const prepare = useMutation({
    mutationFn: () => api.post("/api/v1/pki/prepare", { reason: reason.trim() }),
    onSuccess: () => { setReason(""); refresh(); },
    onError,
  });
  const activate = useMutation({
    mutationFn: () => api.post("/api/v1/pki/activate", { reason: reason.trim() }),
    onSuccess: () => { setReason(""); refresh(); },
    onError,
  });
  const remove = useMutation({
    mutationFn: ({ fingerprint, reason }: { fingerprint: string; reason: string }) =>
      api.del(`/api/v1/pki/${fingerprint}?reason=${encodeURIComponent(reason)}`),
    onSuccess: refresh,
    onError,
  });

  if (query.error instanceof ApiError && query.error.forbidden) {
    return <Empty>{t("You do not have permission to view the fleet CA.")}</Empty>;
  }
  if (query.error) return <ErrorBox error={query.error} />;

  const list = query.data?.authorities ?? [];
  const pending = list.find((ca) => ca.state === "pending");
  const reasonReady = reason.trim().length >= 8;

  return (
    <>
      <p className="subtitle">
        {t("Agent certificates are issued by the fleet CA. Rotation happens in two phases: the new CA first reaches agents as their certificates are renewed, and only then takes over signing.")}
      </p>

      <table>
        <thead>
          <tr>
            <th>{t("State")}</th><th>{t("Serial")}</th><th>{t("Valid until")}</th>
            <th>{t("Certificates")}</th><th>{t("Notes")}</th><th /></tr>
        </thead>
        <tbody>
          {list.map((ca) => (
            <tr key={ca.fingerprint}>
              <td><AuthorityState state={ca.state} /></td>
              <td title={ca.fingerprint}>{ca.serial.slice(0, 14)}…</td>
              <td><Time value={ca.not_after} /></td>
              <td>{ca.hosts_using}</td>
              <td className="source">
                {ca.state === "pending" && (
                  ca.ready_to_activate
                    ? t("the whole fleet already knows this CA")
                    : t("{n} hosts do not know it yet", { n: ca.hosts_missing ?? 0 })
                )}
                {ca.state === "retired" && ca.hosts_using > 0 &&
                  t("still used by hosts")}
                {ca.state === "active" && t("signs new certificates")}
              </td>
              <td>
                {ca.state === "retired" && ca.hosts_using === 0 && (
                  <button
                    onClick={() => {
                      const reason = window.prompt(t("Reason for removing this CA from the trust set (min. 8 characters):"));
                      if (reason) remove.mutate({ fingerprint: ca.fingerprint, reason });
                    }}
                  >
                    {t("Remove from trust set")}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="form" style={{ marginTop: 24 }}>
        <h2>{pending ? t("Phase 2: hand over signing") : t("Phase 1: prepare a new CA")}</h2>
        <p className="subtitle">
          {pending
            ? pending.ready_to_activate
              ? t("The whole fleet already knows the new CA. After the handover the previous CA stays trusted, so current agent certificates remain valid.")
              : t("The new CA is already being distributed. Handing over signing becomes possible once every host has renewed its certificate ({n} remaining).", { n: pending.hosts_missing ?? 0 })
            : t("The new CA will join the trust set and reach agents as their certificates are renewed. Signing stays with the current CA.")}
        </p>
        <label>{t("Reason for the change")}
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={t("e.g. planned CA rotation before expiry")}
          />
        </label>
        <div className="operations">
          {pending ? (
            <button
              disabled={!reasonReady || !pending.ready_to_activate || activate.isPending}
              onClick={() => activate.mutate()}
            >
              {t("Hand signing over to the new CA")}
            </button>
          ) : (
            <button disabled={!reasonReady || prepare.isPending} onClick={() => prepare.mutate()}>
              {t("Prepare a new CA")}
            </button>
          )}
        </div>
      </div>
    </>
  );
}

function AuthorityState({ state }: { state: Authority["state"] }) {
  const t = useT();
  switch (state) {
    case "active":
      return <span className="badge ok">{t("signing")}</span>;
    case "pending":
      return <span className="badge warn">{t("prepared")}</span>;
    default:
      return <span className="badge">{t("retired")}</span>;
  }
}
