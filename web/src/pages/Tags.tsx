import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { Whoami } from "../lib/types";
import { Board } from "../components/board";
import { ErrorBox } from "../components/ui";
import { Actions, Empty, Field, Fields, PageHead, Panel, Toolbar } from "../ui/kit";
import { Breakdown, StatusBar } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The tag catalogue: every tag the visible hosts carry, in one place. A tag
 * is set on the host page, one host at a time, and that is where it belongs.
 */

/** One tag of the catalogue with the number of visible hosts carrying it. */
type TagCount = { tag: string; hosts: number };

/** What the rename answered: how many hosts moved. */
type RenameResult = { from: string; to: string; hosts: number; host_ids: string[] };

/** A tag taken apart: the key, and the value when it has one. */
function splitTag(tag: string): { key: string; value?: string } {
  const at = tag.indexOf("=");
  return at < 0 ? { key: tag } : { key: tag.slice(0, at), value: tag.slice(at + 1) };
}

/** The host list narrowed to one tag. */
export function hostsWithTag(tag: string): string {
  return `/hosts?tag=${encodeURIComponent(tag)}`;
}

export function Tags() {
  const t = useT();
  const [filter, setFilter] = useState("");
  const [renaming, setRenaming] = useState<TagCount | null>(null);
  const catalogue = useQuery({
    queryKey: ["tags"],
    queryFn: () => api.get<Collection<TagCount>>("/api/v1/tags"),
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canRename = (whoami.data?.permissions ?? []).includes("host.tag.write");

  const items = catalogue.data?.items ?? [];
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return needle ? items.filter((item) => item.tag.toLowerCase().includes(needle)) : items;
  }, [items, filter]);
  // The keys of the key=value tags, counted by their values: a key with
  // many values is a dimension of the fleet, and reads as one.
  const byKey = useMemo(() => {
    const keys = new Map<string, number>();
    for (const item of items) {
      const { key, value } = splitTag(item.tag);
      if (value !== undefined) keys.set(key, (keys.get(key) ?? 0) + 1);
    }
    return [...keys.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 12);
  }, [items]);
  const loaded = catalogue.data !== undefined;
  const plain = items.filter((item) => splitTag(item.tag).value === undefined).length;
  const tagged = items.reduce((sum, item) => sum + item.hosts, 0);

  if (catalogue.error) return <ErrorBox error={catalogue.error} />;

  return (
    <>
      <PageHead
        icon="hosts"
        title={t("Tags")}
        description={t("Every tag your hosts carry, and how many carry it.")}
        help={<p>{t("Every tag the hosts you may read carry, with how many carry it. A tag is set on the host page; here it is found, followed to its hosts and, when it is spelled two ways, renamed on every host at once.")}</p>}
      />

      <Board
        screen="tags"
        catalogue={[
          { key: "catalogue", title: "Catalogue", width: 8 },
          { key: "by_key", title: "By key", width: 4 },
          { key: "list", title: "Tags", width: 12 },
        ]}
        drawn={{
          catalogue: (
            <>
              <Panel className="ui-col-8" title={t("Catalogue")} description={t("{n} tags on the hosts you may read", { n: items.length })}>
          <StatusBar segments={[
            { label: t("Tags"), value: loaded ? items.length : undefined, tone: "info" },
            { label: t("Plain"), value: loaded ? plain : undefined, tone: "neutral" },
            { label: t("Key=value"), value: loaded ? items.length - plain : undefined, tone: "ok" },
            // A host with three tags counts three times here: it is the
            // number of assignments, not of tagged hosts.
            { label: t("Assignments"), value: loaded ? tagged : undefined, tone: "info" },
          ]} />
        </Panel>
            </>
          ),
          by_key: (
            <>
              <Panel className="ui-col-4" title={t("By key")} description={t("The keys with the most values.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : byKey.length === 0 ? (
            <p className="ui-empty">{t("No key=value tag.")}</p>
          ) : (
            <Breakdown tone="info" items={byKey.map(([key, n]) => ({ label: <span className="ui-mono">{key}</span>, value: n }))} />
          )}
        </Panel>

        {renaming && (
          <RenameTag
            tag={renaming}
            onDone={() => setRenaming(null)}
          />
        )}
            </>
          ),
          list: (
            <>
              <Panel className="ui-col-12" flush>
          <Toolbar>
            <input
              type="search"
              placeholder={t("Filter tags")}
              aria-label={t("Filter tags")}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </Toolbar>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : items.length === 0 ? (
            <Empty action={<Link className="ui-btn ui-btn-secondary" to="/hosts">{t("Open the host list")}</Link>}>
              {t("No host you may read carries a tag. Tags are set on the host page, under Overview.")}
            </Empty>
          ) : shown.length === 0 ? (
            <Empty>{t("No tag matches the filter.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("Tag")}</th>
                  <th scope="col">{t("Key")}</th>
                  <th scope="col">{t("Value")}</th>
                  <th scope="col" className="ui-numeric">{t("Hosts")}</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {shown.map((item) => {
                  const { key, value } = splitTag(item.tag);
                  return (
                    <tr key={item.tag} data-testid="tag-row" data-tag={item.tag}>
                      <td><span className="ui-tag ui-tag">{item.tag}</span></td>
                      <td className="ui-mono">{key}</td>
                      <td className="ui-mono">{value ?? <span className="ui-note">—</span>}</td>
                      <td className="ui-numeric">{item.hosts}</td>
                      <td className="ui-actioncell">
                        <Actions>
                          <Link className="ui-btn ui-btn-secondary" to={hostsWithTag(item.tag)}>{t("Hosts with this tag")}</Link>
                          {canRename && (
                            <button
                              className="ui-btn-secondary"
                              onClick={() => setRenaming(renaming?.tag === item.tag ? null : item)}
                              aria-expanded={renaming?.tag === item.tag}
                            >
                              {t("Rename")}
                            </button>
                          )}
                        </Actions>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
            </>
          )
        }}
      />
    </>
  );
}

/**
 * Renaming one tag on every host that carries it.
 */
function RenameTag({ tag, onDone }: { tag: TagCount; onDone: () => void }) {
  const t = useT();
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [to, setTo] = useState(tag.tag);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  const rename = useMutation({
    mutationFn: () => api.post<RenameResult>("/api/v1/tags/rename", { from: tag.tag, to: to.trim(), reason: reason.trim() }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["host"] });
      toast.success(t("{from} renamed to {to} on {n} hosts.", { from: result.from, to: result.to, n: result.hosts }), {
        link: { to: hostsWithTag(result.to), label: t("Hosts with this tag") },
      });
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "tag_not_found") {
        setMessage(t("No host you may change carries this tag any more; the catalogue is read again."));
        queryClient.invalidateQueries({ queryKey: ["tags"] });
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const target = to.trim();
  // The same shape the server accepts: selector.TagPattern, spelled here
  // so the field can say so before the request leaves.
  const validTarget = /^[a-z0-9][a-z0-9_.-]*(=[a-zA-Z0-9_.:/-]+)?$/.test(target) && target.length <= 128;
  const ready = validTarget && target !== tag.tag && reason.trim().length >= 8;

  const ask = async () => {
    const { ok } = await confirm({
      title: t("Rename {from} to {to}?", { from: tag.tag, to: target }),
      body: (
        <p>
          {t("Every host you may change that carries {from} - {n} on the hosts you may read - gets {to} instead, in one step. Selectors, groups and campaign schedules that name the old tag keep naming it and match nothing until they are changed.", { from: tag.tag, to: target, n: tag.hosts })}
        </p>
      ),
      confirmLabel: t("Rename"),
      danger: true,
    });
    if (ok) rename.mutate();
  };

  return (
    <Panel
      className="ui-col-12"
      title={t("Rename {tag}", { tag: tag.tag })}
      description={t("The tag changes its name on every host carrying it that you may change; the rest keep the old one and stay in the catalogue.")}
      footer={
        <Actions>
          <button onClick={ask} disabled={!ready || rename.isPending}>{rename.isPending ? t("Renaming…") : t("Rename")}</button>
          <button className="ui-btn-secondary" onClick={onDone} disabled={rename.isPending}>{t("Cancel")}</button>
          {message && <span className="ui-errorbox">{message}</span>}
        </Actions>
      }
    >
      <Fields>
        <Field label={t("New name")} hint={validTarget || !target ? t("key or key=value, lower-case key; a host already carrying the new name ends up with it once.") : t("Not a tag: key or key=value, lower-case key.")}>
          <input
            className="ui-mono"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            autoFocus
            aria-invalid={Boolean(target) && !validTarget}
            data-testid="rename-to"
          />
        </Field>
        <Field label={t("Reason")} hint={t("Required, at least 8 characters; kept in the audit trail with every host.")}>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("unifying the spelling, ticket number")} data-testid="rename-reason" />
        </Field>
      </Fields>
    </Panel>
  );
}
