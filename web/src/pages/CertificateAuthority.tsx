import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Authority } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Actions, Card, Field, FieldGrid } from "../components/layout";
import { Breakdown, StatusBar, type WidgetTone } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
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
  const confirm = useConfirm();
  const toast = useToast();

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
    mutationFn: ({ fingerprint, reason }: { fingerprint: string; reason: string; serial: string }) =>
      api.del(`/api/v1/pki/${fingerprint}?reason=${encodeURIComponent(reason)}`),
    onSuccess: (_, { serial }) => {
      // The row is gone with the refresh, so the outcome is told elsewhere.
      toast.success(t("Authority {serial} is removed from the trust set.", { serial }));
      refresh();
    },
    onError,
  });
  // The removal is a step-up operation: the API records the reason and
  // wants at least eight characters of it, so the dialog holds the confirm
  // back until there are.
  const askToRemove = async (ca: Authority) => {
    const answer = await confirm({
      title: t("Remove from trust set"),
      body: t("Authority {serial} leaves the trust set: no host holds a certificate it issued, and the agents stop trusting it as their certificates are renewed.", { serial: ca.serial.slice(0, 14) }),
      confirmLabel: t("Remove from trust set"),
      danger: true,
      reason: { required: true, min: 8 },
    });
    if (answer.ok && answer.reason) remove.mutate({ fingerprint: ca.fingerprint, reason: answer.reason, serial: ca.serial.slice(0, 14) });
  };

  if (query.error instanceof ApiError && query.error.forbidden) {
    return <Card><Empty>{t("You do not have permission to view the fleet CA.")}</Empty></Card>;
  }
  if (query.error) return <ErrorBox error={query.error} />;

  const list = query.data?.authorities ?? [];
  const pending = list.find((ca) => ca.state === "pending");
  const reasonReady = reason.trim().length >= 8;
  // The trust set by state: one authority signs, at most one is prepared,
  // and the retired ones stay until no host holds a certificate of theirs.
  // Before the answer arrives nothing is known, and the bar shows dashes.
  const count = (state: Authority["state"]) => (query.data ? list.filter((ca) => ca.state === state).length : undefined);
  const holding = list.filter((ca) => ca.hosts_using > 0);
  const holdingTone = (state: Authority["state"]): WidgetTone => (state === "active" ? "ok" : state === "pending" ? "warn" : "info");

  // The trust set and the step that changes it stand side by side: the
  // operator reads the fingerprints on the left and acts on the right.
  return (
    <div className="widgets">
      <Card className="span-8" title={t("Trust set")} description={t("{n} authorities", { n: list.length })}>
        <StatusBar segments={[
          { label: t("signing"), value: count("active"), tone: "ok" },
          { label: t("prepared"), value: count("pending"), tone: "warn" },
          { label: t("retired"), value: count("retired"), tone: "unknown" },
        ]} />
      </Card>

      {/* Which authority the agents' certificates hang on: a retired CA
          with hosts still holding its certificates cannot leave the trust
          set yet, and that is read here before the row says so. */}
      <Card className="span-4" title={t("Certificates by authority")} description={t("Agent certificates each authority issued.")}>
        {!query.data ? (
          <Empty>{t("Loading…")}</Empty>
        ) : holding.length === 0 ? (
          <p className="fp-blank">{t("No host holds a certificate of any authority.")}</p>
        ) : (
          <Breakdown items={holding.map((ca) => ({
            label: <><span className="mono">{ca.serial.slice(0, 8)}</span> <AuthorityState state={ca.state} /></>,
            value: ca.hosts_using,
            tone: holdingTone(ca.state),
          }))} />
        )}
      </Card>

      <Card
        className="span-8"
        title={t("Fleet CA")}
        description={t("Agent certificates are issued by the fleet CA. Rotation happens in two phases: the new CA first reaches agents as their certificates are renewed, and only then takes over signing.")}
        flush
      >
        <table>
          <thead>
            <tr>
              <th>{t("State")}</th><th>{t("Serial")}</th><th>{t("Valid until")}</th>
              <th className="num">{t("Certificates")}</th><th>{t("Notes")}</th><th /></tr>
          </thead>
          <tbody>
            {list.map((ca) => (
              <tr key={ca.fingerprint}>
                <td><AuthorityState state={ca.state} /></td>
                <td className="mono" title={ca.fingerprint}>{ca.serial.slice(0, 14)}…</td>
                <td><Time value={ca.not_after} /></td>
                <td className="num">{ca.hosts_using}</td>
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
                <td className="actions-cell">
                  {ca.state === "retired" && ca.hosts_using === 0 && (
                    <div className="row-actions">
                      <button
                        className="danger"
                        disabled={remove.isPending}
                        onClick={() => askToRemove(ca)}
                      >
                        {t("Remove from trust set")}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card
        className="span-4"
        title={pending ? t("Phase 2: hand over signing") : t("Phase 1: prepare a new CA")}
        description={pending
          ? pending.ready_to_activate
            ? t("The whole fleet already knows the new CA. After the handover the previous CA stays trusted, so current agent certificates remain valid.")
            : t("The new CA is already being distributed. Handing over signing becomes possible once every host has renewed its certificate ({n} remaining).", { n: pending.hosts_missing ?? 0 })
          : t("The new CA will join the trust set and reach agents as their certificates are renewed. Signing stays with the current CA.")}
        footer={
          <Actions>
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
          </Actions>
        }
      >
        <FieldGrid>
          <Field label={t("Reason for the change")} wide>
            <input
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder={t("e.g. planned CA rotation before expiry")}
            />
          </Field>
        </FieldGrid>
      </Card>
    </div>
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
