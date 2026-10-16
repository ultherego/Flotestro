import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Authority } from "../../lib/types";
import { useToast } from "../../components/Toast";
import { useT, type Translate } from "../../i18n";
import {
  Actions, Band, Banner, Bars, Bones, Button, Card, Empty, Field, Fields, Modal, Note, Pill,
  Problem, Table, type Tone,
} from "../kit";

/**
 * The fleet CA: what the hosts trust, and the two phases that change it.
 *
 * It is the root of trust of the whole installation. Every agent
 * certificate hangs on one of these authorities, so a reader here is
 * deciding what a thousand machines will accept tomorrow, and the screen
 * is written to be read slowly: the state of each authority, how many
 * certificates still hang on it, and one sentence per row saying what
 * that means for the next step.
 *
 * It is kept in its own file, beside the other screens, because it is
 * its own section - the settings screen only gives it a place to stand.
 */

/**
 * What the server reports about one authority.
 *
 * The shared type names what every authority carries; a prepared one
 * carries two more that only it has, and a count of relays that have not
 * been handed the new authority yet. A relay without it darkens its whole
 * site at the handover, so it is read here rather than left out.
 */
export type FleetAuthority = Authority & {
  issuer_id?: string;
  relays_missing?: number;
};

/** How long a reason has to be before the trail will take it. */
export const CA_REASON_MIN = 8;

/**
 * A key for one change of the trust set.
 *
 * The panel writes the beginning of such a change to the trail before
 * making it, and the key is what tells a repeated request from a second
 * change: the server refuses a key that already began one.
 */
export function changeKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/** Whether a reason will be taken by the trail. */
export function reasonReady(reason: string): boolean {
  return reason.trim().length >= CA_REASON_MIN;
}

/** The colour of a state: what signs is well, what waits wants watching. */
export function authorityTone(state: Authority["state"]): Tone {
  if (state === "active") return "ok";
  if (state === "pending") return "warn";
  return "unknown";
}

/** The one word a state is read as. */
export function authorityStateLabel(t: Translate, state: Authority["state"]): string {
  if (state === "active") return t("signing");
  if (state === "pending") return t("prepared");
  return t("retired");
}

/**
 * The sentence a row carries about itself.
 *
 * It is the part of the screen an operator acts on: whether the handover
 * may happen, and whether an authority may be taken out of the set.
 */
export function authorityNote(t: Translate, ca: FleetAuthority): string {
  if (ca.state === "active") return t("signs new certificates");
  if (ca.state === "pending") {
    if (ca.ready_to_activate) return t("the whole fleet already knows this CA");
    return t("{n} hosts do not know it yet", { n: ca.hosts_missing ?? 0 });
  }
  if (ca.hosts_using > 0) return t("still used by hosts");
  return t("nothing holds its certificates any more");
}

/**
 * The server's refusal, in the panel's words.
 *
 * Each of these is a different thing to do next, and the difference is
 * the whole value of the message: told "the preparation failed" over a CA
 * that was in fact prepared, an operator prepares a second one. Where the
 * refusal carries a number the server counted, its own sentence is kept
 * beside ours rather than dropped.
 */
export function refusalText(t: Translate, error: ApiError): string {
  switch (error.code) {
    case "pki_unavailable":
      return t("This panel does not manage the fleet CA.");
    case "reason_required":
      return t("A change to what the fleet trusts needs a reason of at least eight characters.");
    case "idempotency_key_required":
      return t("The panel sent no key with this change, so the server could not tell a repeat from a second change.");
    case "change_already_started":
      return t("A change has already begun under this key. Read what the installation holds now rather than repeating the request.");
    case "audit_unavailable":
      return t("The beginning of this change could not be written to the trail, so nothing was changed.");
    case "no_pending_ca":
      return t("No CA is prepared for handover.");
    case "hosts_missing_ca":
      return t("Some hosts do not have the new CA yet; wait for their certificates to renew. ({detail})", { detail: error.message });
    case "relays_missing_ca":
      return t("Some relays do not have the new CA yet. A relay without it stops recognising the agents of its site the moment signing moves. ({detail})", { detail: error.message });
    case "prepared_not_announced":
      return t("The CA was prepared and the other instances of this installation were not told of it. Do not hand signing over yet: until they read the trust set again they hand the hosts a bundle without this authority, and the handover would cut those hosts off. Prepare nothing further.");
    case "activated_not_recorded":
      return t("Signing was handed over and the installation record does not name the new authority. The fleet is signing with it; what is missing is the record the other instances read, and they catch up at their next start. Do not hand over again.");
    case "prepare_failed":
      return t("No CA was prepared: {detail}", { detail: error.message });
    case "activate_failed":
      return t("Signing was not handed over: {detail}", { detail: error.message });
    case "ca_in_use":
      return t("The authority stays in the trust set: {detail}", { detail: error.message });
    case "invalid_body":
      return t("The panel sent something the server could not read.");
    default:
      return error.message;
  }
}

/**
 * The refusal of a change to the trust set, said above the board.
 *
 * It is reported upward rather than drawn inside the section: a banner is
 * not a container somebody arranges, and the one thing an operator must
 * not miss is why the fleet's trust did not change.
 */
export function CertificateAuthorityWarning({ error, close }: {
  error: ApiError | null;
  close: () => void;
}) {
  const t = useT();
  if (!error) return null;
  if (error.code === "reauthentication_required") {
    return (
      <Banner
        tone="warn"
        actions={
          <>
            <Button
              onClick={() => {
                const target = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = `/auth/login?step_up=1&redirect=${target}`;
              }}
              testId="ca-step-up"
            >
              {t("Sign in again")}
            </Button>
            <Button kind="quiet" onClick={close}>{t("Close")}</Button>
          </>
        }
      >
        <span data-testid="ca-warning">
          <b>{t("Re-authentication required.")}</b> {error.message}
        </span>
      </Banner>
    );
  }
  return (
    <Banner tone="error" actions={<Button kind="quiet" onClick={close}>{t("Close")}</Button>}>
      <span data-testid="ca-warning">{refusalText(t, error)}</span>
    </Banner>
  );
}

/** What the retirement dialog is being asked about. */
type Retiring = { fingerprint: string; serial: string };

/** The serial as a row prints it: enough of it to tell two apart. */
function shortSerial(serial: string): string {
  return serial.slice(0, 14);
}

export function CertificateAuthority({ mayRotate, reportError }: {
  /** Whether this sign-in may change what the fleet trusts. */
  mayRotate: boolean;
  /** Where a refusal goes: the settings screen draws it above the board. */
  reportError: (error: ApiError | null) => void;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [retiring, setRetiring] = useState<Retiring | null>(null);
  const [retireReason, setRetireReason] = useState("");

  const query = useQuery({
    queryKey: ["pki"],
    queryFn: () => api.get<{ authorities: FleetAuthority[] }>("/api/v1/pki"),
    retry: false,
    refetchInterval: 30_000,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["pki"] });
  const onError = (error: unknown) => reportError(error instanceof ApiError ? error : null);

  const prepare = useMutation({
    mutationFn: () => api.post("/api/v1/pki/prepare",
      { reason: reason.trim(), idempotency_key: changeKey() }),
    onSuccess: () => { reportError(null); setReason(""); void refresh(); },
    onError,
  });
  const activate = useMutation({
    mutationFn: () => api.post("/api/v1/pki/activate",
      { reason: reason.trim(), idempotency_key: changeKey() }),
    onSuccess: () => { reportError(null); setReason(""); void refresh(); },
    onError,
  });
  // Taking an authority out of the trust set is the destructive one, so it
  // is asked first and carries its own reason.
  const remove = useMutation({
    mutationFn: ({ fingerprint, why }: Retiring & { why: string }) =>
      api.del(`/api/v1/pki/${fingerprint}?reason=${encodeURIComponent(why)}`
        + `&idempotency_key=${encodeURIComponent(changeKey())}`),
    onSuccess: (_result, { serial }) => {
      // The row is gone with the refresh, so the outcome is told elsewhere.
      reportError(null);
      toast.success(t("Authority {serial} is removed from the trust set.", { serial }));
      setRetiring(null);
      setRetireReason("");
      void refresh();
    },
    onError: (error) => { setRetiring(null); setRetireReason(""); onError(error); },
  });

  if (query.error instanceof ApiError && query.error.forbidden) {
    return (
      <Card title={t("Fleet CA")}>
        <Empty icon="certificates" testId="ca-forbidden">
          {t("You do not have permission to view the fleet CA.")}
        </Empty>
      </Card>
    );
  }
  if (query.error) {
    return (
      <Card title={t("Fleet CA")}>
        <Problem>
          <span data-testid="ca-unreadable">
            {query.error instanceof ApiError
              ? refusalText(t, query.error)
              : String(query.error)}
          </span>
        </Problem>
      </Card>
    );
  }

  const list = query.data?.authorities ?? [];
  const pending = list.find((ca) => ca.state === "pending");
  // The trust set by state: one authority signs, at most one is prepared,
  // and the retired ones stay until no host holds a certificate of theirs.
  // Before the answer arrives nothing is counted, and a count nobody took
  // is not a count of none.
  const count = (state: Authority["state"]) =>
    (query.data ? list.filter((ca) => ca.state === state).length : undefined);
  // Which authority the agents' certificates hang on: a retired CA with
  // hosts still holding its certificates cannot leave the trust set yet,
  // and that is read here before the row says so.
  const holding = list.filter((ca) => ca.hosts_using > 0);

  return (
    <>
      <Card
        title={t("Fleet CA")}
        note={t("Agent certificates are issued by the fleet CA. Rotation happens in two phases: the new CA first reaches agents as their certificates are renewed, and only then takes over signing.")}
        foot={
          <Rotation
            pending={pending}
            mayRotate={mayRotate}
            reason={reason}
            setReason={setReason}
            working={prepare.isPending || activate.isPending}
            onPrepare={() => prepare.mutate()}
            onActivate={() => activate.mutate()}
          />
        }
      >
        <Band
          testId="ca-trust-set"
          segments={[
            { label: t("signing"), value: count("active"), tone: "ok" },
            { label: t("prepared"), value: count("pending"), tone: "warn" },
            { label: t("retired"), value: count("retired"), tone: "unknown" },
          ]}
        />

        {!query.data ? (
          <Bones rows={2} />
        ) : holding.length === 0 ? (
          <Note testId="ca-none-holding">{t("No host holds a certificate of any authority.")}</Note>
        ) : (
          <Bars
            items={holding.map((ca) => ({
              label: `${ca.serial.slice(0, 8)} · ${authorityStateLabel(t, ca.state)}`,
              value: ca.hosts_using,
              tone: authorityTone(ca.state),
            }))}
          />
        )}

        <Table<FleetAuthority>
          testId="ca-authorities"
          rows={list}
          loading={!query.data}
          keyOf={(ca) => ca.fingerprint}
          rowTestId={(ca) => `authority-${ca.fingerprint}`}
          empty={<Empty icon="certificates">{t("This installation trusts no authority of its own yet.")}</Empty>}
          columns={[
            {
              key: "state",
              head: t("State"),
              cell: (ca) => <Pill tone={authorityTone(ca.state)}>{authorityStateLabel(t, ca.state)}</Pill>,
            },
            {
              key: "serial",
              head: t("Serial"),
              tight: true,
              cell: (ca) => (
                <span
                  className="fl-mono"
                  title={t("Serial {serial}, fingerprint {fingerprint}", {
                    serial: ca.serial,
                    fingerprint: ca.fingerprint,
                  })}
                >
                  {shortSerial(ca.serial)}
                </span>
              ),
            },
            {
              key: "until",
              head: t("Valid until"),
              cell: (ca) => (ca.not_after
                ? <span title={absoluteTime(ca.not_after)}>{relativeTime(ca.not_after)}</span>
                // The lifetime of the root of trust is not a thing to
                // guess at, so an answer without it says so.
                : <Pill tone="unknown">{t("not said")}</Pill>),
            },
            {
              key: "certificates",
              head: t("Certificates"),
              num: true,
              cell: (ca) => ca.hosts_using,
            },
            {
              key: "notes",
              head: t("Notes"),
              cell: (ca) => authorityNote(t, ca),
            },
            {
              key: "act",
              actions: true,
              label: t("What can be done"),
              cell: (ca) => (mayRotate && ca.state === "retired" && ca.hosts_using === 0 ? (
                <Button
                  kind="danger"
                  disabled={remove.isPending}
                  onClick={() => { setRetireReason(""); setRetiring({ fingerprint: ca.fingerprint, serial: shortSerial(ca.serial) }); }}
                  testId={`ca-remove-${ca.fingerprint}`}
                >
                  {t("Remove from trust set")}
                </Button>
              ) : null),
            },
          ]}
        />
      </Card>

      {retiring && (
        <Modal
          title={t("Remove from trust set")}
          onClose={() => setRetiring(null)}
          actions={
            <>
              <Button
                kind="quiet"
                onClick={() => setRetiring(null)}
                disabled={remove.isPending}
                testId="ca-remove-cancel"
              >
                {t("Cancel")}
              </Button>
              <Button
                kind="danger"
                disabled={!reasonReady(retireReason) || remove.isPending}
                onClick={() => remove.mutate({ ...retiring, why: retireReason.trim() })}
                testId="ca-remove-confirm"
              >
                {remove.isPending ? t("Removing…") : t("Remove from trust set")}
              </Button>
            </>
          }
        >
          <Note>
            {t("Authority {serial} leaves the trust set: no host holds a certificate it issued, and the agents stop trusting it as their certificates are renewed.", {
              serial: retiring.serial,
            })}
          </Note>
          <Fields>
            <Field
              label={t("Reason for the change")}
              hint={t("At least eight characters. It is kept on the audit trail beside the authority.")}
              wide
            >
              <input
                value={retireReason}
                onChange={(event) => setRetireReason(event.target.value)}
                placeholder={t("e.g. the last host on the old CA was rebuilt")}
                data-testid="ca-remove-reason"
              />
            </Field>
          </Fields>
        </Modal>
      )}
    </>
  );
}

/**
 * The step that changes the trust set, in whichever phase it is in.
 *
 * One button at a time on purpose: with a CA prepared, preparing another
 * is not a thing anybody wants, and the only question left is whether the
 * fleet is ready for the handover.
 */
function Rotation({ pending, mayRotate, reason, setReason, working, onPrepare, onActivate }: {
  pending?: FleetAuthority;
  mayRotate: boolean;
  reason: string;
  setReason: (value: string) => void;
  working: boolean;
  onPrepare: () => void;
  onActivate: () => void;
}) {
  const t = useT();
  const ready = reasonReady(reason);

  const title = pending ? t("Phase 2: hand over signing") : t("Phase 1: prepare a new CA");
  const body = pending
    ? pending.ready_to_activate
      ? t("The whole fleet already knows the new CA. After the handover the previous CA stays trusted, so current agent certificates remain valid.")
      : t("The new CA is already being distributed. Handing over signing becomes possible once every host has renewed its certificate ({n} remaining).", { n: pending.hosts_missing ?? 0 })
    : t("The new CA will join the trust set and reach agents as their certificates are renewed. Signing stays with the current CA.");

  return (
    <>
      <Note testId="ca-phase"><b>{title}</b> {body}</Note>
      {pending && (pending.relays_missing ?? 0) > 0 && (
        <Note testId="ca-relays-missing">
          {t("{n} relays do not have the new CA yet either. A relay without it stops recognising the agents of its site the moment signing moves.", {
            n: pending.relays_missing ?? 0,
          })}
        </Note>
      )}
      {!mayRotate ? (
        <Note testId="ca-may-not-rotate">
          {t("Only a sign-in that may rotate the fleet CA can prepare one or hand signing over; ask one.")}
        </Note>
      ) : (
        <>
          <Fields>
            <Field
              label={t("Reason for the change")}
              hint={t("At least eight characters. It is kept on the audit trail beside the authority.")}
              wide
            >
              <input
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder={t("e.g. planned CA rotation before expiry")}
                data-testid="ca-reason"
              />
            </Field>
          </Fields>
          <Actions>
            {pending ? (
              <Button
                disabled={!ready || !pending.ready_to_activate || working}
                onClick={onActivate}
                testId="ca-activate"
              >
                {working ? t("Working…") : t("Hand signing over to the new CA")}
              </Button>
            ) : (
              <Button disabled={!ready || working} onClick={onPrepare} testId="ca-prepare">
                {working ? t("Working…") : t("Prepare a new CA")}
              </Button>
            )}
          </Actions>
        </>
      )}
    </>
  );
}
