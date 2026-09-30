import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { InstallationProfile } from "../lib/types";
import { ErrorBox } from "../components/ui";
import { absoluteTime } from "../lib/format";
import { Actions, Field, FieldGrid } from "../components/layout";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The address the agents dial.
 *
 * The screen offers what the panel found on this machine and confirms nothing by
 * itself. The panel cannot tell which of its interfaces the hosts route to, and
 * the wrong one in the certificate is a fleet that enrols and drops out again,
 * so a detected address stays a proposal until somebody says otherwise.
 */

/** One address the panel found on this machine. A proposal, never a setting. */
export type AddressCandidate = {
  name: string;
  kind: "address" | "hostname";
  interface?: string;
  loopback: boolean;
};

/** What the panel advertises, where it came from, and what it proposes. */
export type AdvertisedAddress = {
  in_force: string[];
  source: "environment" | "confirmed" | "default";
  loopback_only: boolean;
  reachable?: string[];
  reserved?: string[];
  environment?: string[];
  environment_in_force: boolean;
  confirmed?: string[];
  confirmed_at?: string;
  confirmed_by?: string;
  superseded?: string[];
  revision?: number;
  mismatch?: string;
  candidates: AddressCandidate[];
  note: string;
};

/** The value of the "something else" choice, which is not a candidate's name. */
export const OWN_ADDRESS = "\u0000own";

/**
 * What the administrator is about to confirm: the picked candidate, or what they
 * typed. A blank choice confirms nothing - the button stays out of reach rather
 * than sending the first proposal.
 */
export function chosenAddress(picked: string, typed: string): string[] {
  const value = (picked === OWN_ADDRESS ? typed : picked).trim();
  return value === "" ? [] : value.split(",").map((part) => part.trim()).filter((part) => part !== "");
}

/**
 * Whether a choice may be sent. It is the panel's own check and not the
 * server's: the server refuses the same things, and a screen that lets the
 * request go out only to show a refusal has made the operator wait for nothing.
 */
export function confirmable(names: string[], environmentInForce: boolean): boolean {
  if (environmentInForce || names.length === 0) return false;
  return names.every((name) => /^[A-Za-z0-9.:_-]+$/.test(name) && !name.includes("/"));
}

/** How a candidate is described in one line, without inventing anything. */
export function candidateNote(candidate: AddressCandidate, t: (s: string, v?: Record<string, string | number>) => string): string {
  if (candidate.kind === "hostname") {
    return candidate.loopback
      ? t("the name this machine answers to, and it resolves to loopback")
      : t("the name this machine answers to");
  }
  const where = candidate.interface
    ? t("on the interface {name}", { name: candidate.interface })
    : t("an address of this machine");
  return candidate.loopback ? t("{where}, reaches only this machine", { where }) : where;
}

/** The badge beside the address in force: where it came from. */
export function sourceTone(source: AdvertisedAddress["source"], loopbackOnly: boolean): "ok" | "warn" | "error" {
  if (loopbackOnly) return "error";
  return source === "default" ? "warn" : "ok";
}

/**
 * The section inside the Setup checklist's step. The step card carries the title
 * and the meaning; this is the state, the proposals and the confirmation.
 */
export function AdvertisedAddressSection({ mayConfirm }: { mayConfirm: boolean }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [picked, setPicked] = useState("");
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [refusal, setRefusal] = useState<ApiError | null>(null);

  const address = useQuery({
    queryKey: ["advertised-address"],
    queryFn: () => api.get<AdvertisedAddress>("/api/v1/settings/advertised"),
  });

  const confirm = useMutation({
    mutationFn: (names: string[]) =>
      api.put<AdvertisedAddress>("/api/v1/settings/advertised", { names, reason: reason.trim() }),
    onSuccess: (state) => {
      setRefusal(null);
      toast.success(t("The agents now dial {names}.", { names: state.in_force.join(", ") }));
      queryClient.invalidateQueries({ queryKey: ["advertised-address"] });
      queryClient.invalidateQueries({ queryKey: ["setup"] });
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      queryClient.invalidateQueries({ queryKey: ["installation-profile"] });
    },
    onError: (error) => setRefusal(error instanceof ApiError ? error : null),
  });

  if (address.error) return <ErrorBox error={address.error} />;
  const state = address.data;
  if (!state) return <p className="source" style={{ marginTop: 12 }}>{t("Loading…")}</p>;

  const names = chosenAddress(picked, typed);
  const ready = confirmable(names, state.environment_in_force);

  return (
    <div style={{ marginTop: 12 }} data-testid="advertised-address">
      <p style={{ margin: 0 }}>
        <strong>{t("In force:")}</strong>{" "}
        <code className="mono">{state.in_force.join(", ")}</code>{" "}
        <span className={`badge ${sourceTone(state.source, state.loopback_only)}`}>
          {state.source === "environment" && t("declared in the deployment")}
          {state.source === "confirmed" && t("confirmed")}
          {state.source === "default" && t("not confirmed")}
        </span>
      </p>
      {state.source === "confirmed" && state.confirmed_by && (
        <p className="source" style={{ marginTop: 6 }}>
          {t("Confirmed by {who} on {when}.", {
            who: state.confirmed_by,
            when: absoluteTime(state.confirmed_at ?? "") || (state.confirmed_at ?? ""),
          })}
        </p>
      )}
      {state.loopback_only && (
        <p className="source" style={{ marginTop: 6 }}>
          {t("This reaches only the machine the panel runs on, so a host elsewhere is turned away at enrolment rather than left to fail a handshake later.")}
        </p>
      )}
      {state.mismatch && (
        <div className="warning" style={{ marginTop: 12 }}>
          <p style={{ margin: 0 }}>{state.mismatch}</p>
        </div>
      )}
      {state.superseded && state.superseded.length > 0 && (
        <p className="source" style={{ marginTop: 6 }}>
          {t("Held back from any relay as well, because an agent not yet reconfigured still dials it: {names}.", {
            names: state.superseded.join(", "),
          })}
        </p>
      )}

      {state.environment_in_force ? (
        <p className="source" style={{ marginTop: 12 }}>
          {t("This installation declares the address in the environment of the control plane ({names}), and that declaration decides. Change it there; a confirmation made here would be refused rather than kept where it does not take effect.", {
            names: (state.environment ?? []).join(", "),
          })}
        </p>
      ) : !mayConfirm ? (
        <p className="source" style={{ marginTop: 12 }}>
          {t("Only a platform administrator names the address the fleet connects to; ask one.")}
        </p>
      ) : (
        <div style={{ marginTop: 14 }}>
          <p style={{ margin: "0 0 8px" }}>
            <strong>{t("Found on this machine")}</strong>{" "}
            <span className="badge unknown">{t("proposal")}</span>
          </p>
          <p className="source" style={{ margin: "0 0 10px" }}>
            {t("The panel read these off its own interfaces. It cannot tell which of them the hosts route to, so none of them is in use until you pick one and confirm it.")}
          </p>
          <FieldGrid>
            {state.candidates.map((candidate) => (
              <div className="field" key={`${candidate.kind}:${candidate.name}`}>
                <label className="toggle">
                  <input
                    type="radio"
                    name="advertised-candidate"
                    value={candidate.name}
                    checked={picked === candidate.name}
                    onChange={() => setPicked(candidate.name)}
                  />{" "}
                  <code className="mono">{candidate.name}</code>
                </label>
                <span className="field-hint">{candidateNote(candidate, t)}</span>
              </div>
            ))}
            <div className="field">
              <label className="toggle">
                <input
                  type="radio"
                  name="advertised-candidate"
                  value={OWN_ADDRESS}
                  checked={picked === OWN_ADDRESS}
                  onChange={() => setPicked(OWN_ADDRESS)}
                />{" "}
                {t("a name of your own")}
              </label>
              <span className="field-hint">
                {t("The DNS name the hosts resolve, which is usually not an address of an interface. Several, separated by commas, are tried in order.")}
              </span>
              <input
                className="mono"
                value={typed}
                placeholder="panel.example.org"
                disabled={picked !== OWN_ADDRESS}
                onChange={(e) => setTyped(e.target.value)}
              />
            </div>
          </FieldGrid>
          <FieldGrid>
            <Field label={t("Reason")} hint={t("Kept on the audit trail beside the names. Optional.")} wide>
              <input value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
          </FieldGrid>
          {refusal && (
            <p className="page-error" style={{ marginTop: 8 }}>
              {refusal.code === "advertised_address_from_environment"
                ? t("The deployment declares the address, so it is not confirmed here.")
                : refusal.message}
            </p>
          )}
          <Actions>
            <button disabled={!ready || confirm.isPending} onClick={() => confirm.mutate(names)}>
              {confirm.isPending
                ? t("Confirming…")
                : names.length > 0
                  ? t("Confirm {names}", { names: names.join(", ") })
                  : t("Confirm the address")}
            </button>
          </Actions>
          <p className="source" style={{ marginTop: 8 }}>{state.note}</p>
        </div>
      )}

      {/* What was just confirmed decides this, not the query: the answer to the
          confirmation is the newest word on the address, and the read behind it
          may still be in flight. */}
      {confirm.data && !confirm.data.loopback_only && <AgentConfiguration />}
    </div>
  );
}

/**
 * What a new host is told, now that the address is settled. It is read from the
 * installation profile rather than composed here: that is the same file the
 * operator pastes onto a host, so a screen that rebuilt it could agree with
 * nothing.
 */
function AgentConfiguration() {
  const t = useT();
  const profile = useQuery({
    queryKey: ["installation-profile", "advertised-address"],
    queryFn: () =>
      api.get<InstallationProfile>("/api/v1/installation-profiles?kind=agent"),
  });
  if (profile.error) return <ErrorBox error={profile.error} />;
  const data = profile.data;
  if (!data) return <p className="source" style={{ marginTop: 12 }}>{t("Loading…")}</p>;
  return (
    <div style={{ marginTop: 16 }}>
      <p style={{ margin: "0 0 6px" }}>
        <strong>{t("The agent configuration that now applies")}</strong>
      </p>
      <p className="source" style={{ margin: "0 0 8px" }}>
        {t("This is what the add-host screen hands out from now on; it is written to {path} on the host.", { path: data.config.path })}
      </p>
      <pre className="mono" data-testid="advertised-agent-config">{data.config.content}</pre>
      {(data.warnings ?? []).map((warning) => (
        <p className="source" key={warning}>{warning}</p>
      ))}
    </div>
  );
}
