import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Check, Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type HostKey = { type: string; bits: number; fingerprint: string; path: string };

type Snapshot = {
  ports?: string[];
  listen_addresses?: string[];
  permit_root_login?: string;
  password_authentication?: string;
  pubkey_authentication?: string;
  kbd_interactive_authentication?: string;
  gssapi_authentication?: string;
  max_auth_tries?: number;
  allow_users?: string[];
  allow_groups?: string[];
  deny_users?: string[];
  deny_groups?: string[];
  host_keys?: HostKey[];
  managed_config?: string;
  managed_path?: string;
  managed_present?: boolean;
  unit?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/**
 * Whether the snapshot carries nothing of what "sshd -T" prints. The
 * server always names a port and a root login policy; a snapshot with
 * neither came from a read that got no output and left no reason.
 */
export function effectiveConfigurationMissing(snapshot: Pick<Snapshot, "ports" | "permit_root_login" | "password_authentication" | "pubkey_authentication">): boolean {
  return (snapshot.ports ?? []).length === 0 && !snapshot.permit_root_login && !snapshot.password_authentication && !snapshot.pubkey_authentication;
}

/**
 * The sshd server.
 *
 * The panel writes only its own file in sshd_config.d: the main file belongs
 * to the distribution and the host administrator. The state is shown as the
 * server itself reports it - in sshd the first value wins, so assembling it
 * from file contents would give a picture the host does not confirm.
 */
export function SshServer() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "ssh");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [editor, setEditor] = useState(false);

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
      setEditor(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its sshd yet.")}</Empty>;

  const methods: [string, string | undefined][] = [
    [t("Password"), snapshot?.password_authentication],
    [t("Public key"), snapshot?.pubkey_authentication],
    [t("Keyboard interactive"), snapshot?.kbd_interactive_authentication],
    ["GSSAPI", snapshot?.gssapi_authentication],
  ];
  // An unread configuration has nothing to count; the bar shows dashes
  // then. A snapshot without a reason but without a single setting from
  // "sshd -T" is unread too: the host keys came from the disk, the
  // effective configuration did not, and a zero port count would say the
  // server listens nowhere.
  const effectiveMissing = !!snapshot && !snapshot.unavailable_reason && effectiveConfigurationMissing(snapshot);
  const known = snapshot?.unavailable_reason || effectiveMissing ? undefined : snapshot;
  const knownMethods = known ? methods : undefined;
  const risky = (value?: string) => value === "yes" ? "badge warn" : value === "no" ? "badge ok" : "badge unknown";
  // MaxAuthTries is never zero in a configuration sshd printed; a zero is
  // the value of a field the read left empty.
  const maxAuthTries = snapshot?.max_auth_tries ? snapshot.max_auth_tries : undefined;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("SSH")}
        description={t("Effective configuration as sshd itself reports it. The panel writes only its own file in sshd_config.d — the main config belongs to the distribution and to whoever runs this host.")}
        actions={
          <button onClick={() => setEditor((open) => !open)}>
            {editor ? t("Cancel") : t("Change configuration")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("sshd configuration could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}
      {effectiveMissing && (
        <p className="warning">
          <span>{t("The host returned no effective configuration: the read of sshd -T gave nothing, so the ports, the methods and the limits are unknown. The host keys were read from disk.")}</span>
        </p>
      )}

      <Widgets>
      {/* The ways in, counted: ports, methods, keys. Beside them the two
          settings that decide most break-ins, as badges, and the access
          lists by length. */}
      <Summary
        title={t("Ways in")}
        description={t("What sshd listens on and accepts, as it reports it.")}
        span={8}
        segments={[
          { label: t("ports"), value: known ? (known.ports ?? []).length : undefined, tone: "info" },
          { label: t("methods enabled"), value: countWhere(knownMethods, ([, value]) => value === "yes"), tone: "warn" },
          { label: t("methods disabled"), value: countWhere(knownMethods, ([, value]) => value === "no"), tone: "ok" },
          { label: t("methods unknown"), value: countWhere(knownMethods, ([, value]) => value !== "yes" && value !== "no"), tone: "unknown" },
          // The keys come from the disk, not from "sshd -T": they are
          // counted whenever the snapshot carries them, even when the
          // effective configuration could not be read.
          { label: t("host keys"), value: snapshot?.host_keys ? snapshot.host_keys.length : undefined, tone: "neutral" },
        ]}
      />
      <Section title={t("Posture")} span={4} flush>
        <Facts>
          {/* "prohibit-password" is neither yes nor no - we show what the
              server said, not a translation into a flag. */}
          <Fact label={t("Root login")}>
            <span className={risky(snapshot?.permit_root_login)}>{snapshot?.permit_root_login || t("unknown")}</span>
          </Fact>
          <Fact label={t("Password")}>
            <span className={risky(snapshot?.password_authentication)}>{snapshot?.password_authentication || t("unknown")}</span>
          </Fact>
          <Fact label={t("Max auth tries")}>{maxAuthTries ?? <span className="badge unknown">{t("unknown")}</span>}</Fact>
          <Fact label={t("Access lists")} wide>
            {known ? (
              <Breakdown
                items={[
                  { label: t("Allow users"), value: (known.allow_users ?? []).length, tone: "ok" },
                  { label: t("Allow groups"), value: (known.allow_groups ?? []).length, tone: "ok" },
                  { label: t("Deny users"), value: (known.deny_users ?? []).length, tone: "error" },
                  { label: t("Deny groups"), value: (known.deny_groups ?? []).length, tone: "error" },
                ]}
              />
            ) : "—"}
          </Fact>
        </Facts>
      </Section>

      {editor && <SshEditor state={snapshot} onIntent={setIntent} />}

      {/* The facts and the short method table share a row; the keys and
          the drop-in below share the next one. */}
      <Section title={t("Effective configuration")} span={7} flush>
        <Facts>
          <Fact label={t("Port")}><span className="hm-mono">{(snapshot?.ports ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Listening on")}><span className="hm-mono">{(snapshot?.listen_addresses ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Root login")}>{snapshot?.permit_root_login || "—"}</Fact>
          <Fact label={t("Max auth tries")}>{maxAuthTries ?? "—"}</Fact>
          <Fact label={t("Allow users")}><span className="hm-mono">{(snapshot?.allow_users ?? []).join(" ") || "—"}</span></Fact>
          <Fact label={t("Allow groups")}><span className="hm-mono">{(snapshot?.allow_groups ?? []).join(" ") || "—"}</span></Fact>
          <Fact label={t("Deny users")}><span className="hm-mono">{(snapshot?.deny_users ?? []).join(" ") || "—"}</span></Fact>
          <Fact label={t("Service unit")}><span className="hm-mono">{snapshot?.unit || "—"}</span></Fact>
        </Facts>
      </Section>

      <Section title={t("Authentication methods")} span={5} flush>
        <Table>
          <thead><tr><th>{t("Method")}</th><th>{t("Enabled")}</th></tr></thead>
          <tbody>
            {methods.map(([name, value]) => (
              <tr key={name}>
                <td className="hm-primary">{name}</td>
                <td>{value || <span className="badge unknown">{t("unknown")}</span>}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      <Section
        title={t("Host keys")}
        count={(snapshot?.host_keys ?? []).length}
        span={7}
        description={t("Fingerprints only — the panel has no reason to see a host's private key. Rotating one changes this host's identity for every client that has it in known_hosts.")}
        flush
      >
        <Table>
          <thead><tr><th>{t("Type")}</th><th className="hm-num">{t("Bits")}</th><th>{t("Fingerprint")}</th><th>{t("Actions")}</th></tr></thead>
          <tbody>
            {(snapshot?.host_keys ?? []).map((key) => (
              <tr key={key.path}>
                <td className="hm-primary">{key.type}</td>
                <td className="hm-num">{key.bits}</td>
                <td className="source hm-mono">{key.fingerprint}</td>
                <td>
                  <button
                    className="hm-danger"
                    onClick={() =>
                      setIntent({
                        action: "ssh.hostkey.rotate",
                        label: t("Rotate host key"),
                        description: t("A new {type} host key will be generated on {host}. Every client with the old fingerprint in known_hosts will warn, and anything keyed to the old fingerprint stops working. The old key is kept on the host with a timestamp.", {
                          type: key.type, host: host.hostname,
                        }),
                        payload: { ssh: { key_type: key.type } },
                      })
                    }
                  >
                    {t("Rotate")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      <Section title={t("Managed drop-in")} description={<span className="hm-mono">{snapshot?.managed_path}</span>} span={5} flush>
        {snapshot?.managed_present ? (
          <div className="hm-section-body">
            <pre>{snapshot.managed_config}</pre>
          </div>
        ) : (
          <Empty>{t("The panel has not written anything to this host yet.")}</Empty>
        )}
      </Section>
      </Widgets>

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Configuration read")} <Time value={snapshot.observed_at} /></span>
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

/**
 * The managed file editor. An empty field means "do not change": the panel
 * does not rewrite the whole server configuration, only what the operator
 * asked for.
 */
function SshEditor({
  state, onIntent,
}: {
  state?: Snapshot;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const [root, setRoot] = useState("");
  const [password, setPassword] = useState("");
  const [pubkey, setPubkey] = useState("");
  const [tries, setTries] = useState("");
  const [groups, setGroups] = useState("");
  const [lockout, setLockout] = useState(false);

  const list = (value: string) => value.split(/[\s,]+/).filter(Boolean);
  const change: Record<string, unknown> = {};
  if (root) change.permit_root_login = root;
  if (password) change.password_authentication = password;
  if (pubkey) change.pubkey_authentication = pubkey;
  if (tries) change.max_auth_tries = tries;
  if (groups) change.allow_groups = list(groups);
  if (lockout) change.allow_lockout = true;

  return (
    <Section
      title={t("Change configuration")}
      description={t("Empty means “leave it alone”. The host validates the file with sshd itself before reloading, and reloads instead of restarting so open sessions survive.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Root login")}>
            <select value={root} onChange={(e) => setRoot(e.target.value)}>
              <option value="">{t("root login: leave")}</option>
              <option value="no">{t("root login: no")}</option>
              <option value="prohibit-password">{t("root login: keys only")}</option>
              <option value="yes">{t("root login: yes")}</option>
            </select>
          </Field>
          <Field label={t("Password")}>
            <select value={password} onChange={(e) => setPassword(e.target.value)}>
              <option value="">{t("password auth: leave")}</option>
              <option value="no">{t("password auth: no")}</option>
              <option value="yes">{t("password auth: yes")}</option>
            </select>
          </Field>
          <Field label={t("Public key")}>
            <select value={pubkey} onChange={(e) => setPubkey(e.target.value)}>
              <option value="">{t("public key auth: leave")}</option>
              <option value="yes">{t("public key auth: yes")}</option>
              <option value="no">{t("public key auth: no")}</option>
            </select>
          </Field>
          <Field label="MaxAuthTries" narrow>
            <input value={tries} onChange={(e) => setTries(e.target.value)} placeholder="MaxAuthTries" />
          </Field>
          <Field label="AllowGroups">
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="AllowGroups" />
          </Field>
        </Fields>
        {/* A server nobody can log into by any method is not secured - it is
            unreachable. */}
        <Check checked={lockout} onChange={setLockout}>
          {t("Allow a configuration that leaves no working authentication method")}
        </Check>
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                action: "ssh.config.apply",
                label: t("Apply sshd configuration"),
                description: t("{changes} on {unit}. Existing sessions stay open.", {
                  changes: Object.entries(change)
                    .filter(([key]) => key !== "allow_lockout")
                    .map(([key, value]) => `${key} = ${Array.isArray(value) ? value.join(" ") : value}`)
                    .join(", "),
                  unit: state?.unit ?? "sshd",
                }),
                payload: { ssh: change },
              })
            }
            disabled={Object.keys(change).filter((key) => key !== "allow_lockout").length === 0}
          >
            {t("Apply")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
