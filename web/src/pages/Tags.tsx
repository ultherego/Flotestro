import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { Whoami } from "../lib/types";
import { Empty, ErrorBox } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { Breakdown, StatusBar } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The tag catalogue: every tag the visible hosts carry, in one place.
 *
 * A tag is set on the host page, one host at a time, and that is where
 * it belongs. But "which tags does this fleet use" and "is web the same
 * thing as www" cannot be answered host by host, and a tag spelled two
 * ways is a selector that matches half the hosts it should. This page
 * answers the first question and mends the second: a rename moves every
 * host the operator may change from the old name to the new one, in one
 * transaction, with a reason on the trail.
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
      <PageHeader
        icon="hosts"
        title={t("Tags")}
        description={t("Every tag the hosts you may read carry, with how many carry it. A tag is set on the host page; here it is found, followed to its hosts and, when it is spelled two ways, renamed on every host at once.")}
      />

      <div className="widgets">
        <Card className="span-8" title={t("Catalogue")} description={t("{n} tags on the hosts you may read", { n: items.length })}>
          <StatusBar segments={[
            { label: t("Tags"), value: loaded ? items.length : undefined, tone: "info" },
            { label: t("Plain"), value: loaded ? plain : undefined, tone: "neutral" },
            { label: t("Key=value"), value: loaded ? items.length - plain : undefined, tone: "ok" },
            { label: t("Host tags"), value: loaded ? tagged : undefined, tone: "info" },
          ]} />
        </Card>
        <Card className="span-4" title={t("By key")} description={t("The keys with the most values.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : byKey.length === 0 ? (
            <p className="fp-blank">{t("No key=value tag.")}</p>
          ) : (
            <Breakdown tone="info" items={byKey.map(([key, n]) => ({ label: <span className="mono">{key}</span>, value: n }))} />
          )}
        </Card>

        {renaming && (
          <RenameTag
            tag={renaming}
            onDone={() => setRenaming(null)}
          />
        )}

        <Card className="span-12" flush>
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
            <Empty>{t("No host you may read carries a tag. Tags are set on the host page, under Overview.")}</Empty>
          ) : shown.length === 0 ? (
            <Empty>{t("No tag matches the filter.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Tag")}</th>
                  <th>{t("Key")}</th>
                  <th>{t("Value")}</th>
                  <th className="num">{t("Hosts")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((item) => {
                  const { key, value } = splitTag(item.tag);
                  return (
                    <tr key={item.tag} data-testid="tag-row" data-tag={item.tag}>
                      <td><span className="chip chip-tag">{item.tag}</span></td>
                      <td className="mono">{key}</td>
                      <td className="mono">{value ?? <span className="source">—</span>}</td>
                      <td className="num">{item.hosts}</td>
                      <td className="actions-cell">
                        <Actions>
                          <Link className="button secondary" to={hostsWithTag(item.tag)}>{t("Hosts with this tag")}</Link>
                          {canRename && (
                            <button
                              className="secondary"
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
        </Card>
      </div>
    </>
  );
}

/**
 * Renaming one tag on every host that carries it. The new name is
 * checked the way a tag on the host page is; the reason is required,
 * because the rename touches every host at once and the trail must say
 * why. A host the operator may not change keeps the old tag, and the
 * answer says how many moved.
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
    <Card
      className="span-12"
      title={t("Rename {tag}", { tag: tag.tag })}
      description={t("The tag changes its name on every host carrying it that you may change; the rest keep the old one and stay in the catalogue.")}
      footer={
        <Actions>
          <button onClick={ask} disabled={!ready || rename.isPending}>{rename.isPending ? t("Renaming…") : t("Rename")}</button>
          <button className="secondary" onClick={onDone} disabled={rename.isPending}>{t("Cancel")}</button>
          {message && <span className="page-error">{message}</span>}
        </Actions>
      }
    >
      <FieldGrid>
        <Field label={t("New name")} hint={validTarget || !target ? t("key or key=value, lower-case key; a host already carrying the new name ends up with it once.") : t("Not a tag: key or key=value, lower-case key.")}>
          <input
            className="mono"
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
      </FieldGrid>
    </Card>
  );
}
