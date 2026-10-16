import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { useToast } from "../../components/Toast";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Band, Bars, Card, Empty, Field, Fields, Find, Kpi, Modal, Note, Problem, Table, Toolbar,
  type Segment,
} from "../kit";

/**
 * The tags: what operators recorded about the hosts, gathered in one place.
 *
 * A tag is written on a host, one host at a time, and that is where it
 * belongs. What this screen is for is the other direction - finding the
 * word that was spelled two ways, seeing which keys the fleet is really
 * divided by, and putting one spelling right everywhere at once.
 */

/** One tag of the catalogue, with the hosts the reader may see carrying it. */
export type TagCount = { tag: string; hosts: number };

/** What a rename answered: how many hosts moved. */
type RenameResult = { from: string; to: string; hosts: number; host_ids: string[] };

/** A tag taken apart: the key, and the value when it has one. */
export function splitTag(tag: string): { key: string; value?: string } {
  const at = tag.indexOf("=");
  return at < 0 ? { key: tag } : { key: tag.slice(0, at), value: tag.slice(at + 1) };
}

/** The host list narrowed to one tag; the tag's own name leads there. */
export function hostsWithTag(tag: string): string {
  return `/hosts?tag=${encodeURIComponent(tag)}`;
}

/**
 * A name the server will take, spelled here so the field can refuse it
 * before the request leaves. It is the shape of selector.TagPattern.
 */
export function validTagName(tag: string): boolean {
  return tag.length <= 128 && /^[a-z0-9][a-z0-9_.-]*(=[a-zA-Z0-9_.:/-]+)?$/.test(tag);
}

/** How long a reason has to be before the trail will take it. */
export const TAG_REASON_MIN_LENGTH = 8;

export function Tags() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [renaming, setRenaming] = useState(false);

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
  const loaded = catalogue.data !== undefined;
  // `GET /api/v1/tags` takes no query and answers with the whole catalogue
  // the reader may see, so there is no page here to mistake for the answer;
  // the card says how many of how many are drawn.
  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return needle ? items.filter((one) => one.tag.toLowerCase().includes(needle)) : items;
  }, [items, search]);

  const plain = items.filter((one) => splitTag(one.tag).value === undefined).length;
  const assignments = items.reduce((sum, one) => sum + one.hosts, 0);

  // The keys of the key=value tags, counted by how many values each has: a
  // key with many values is a dimension the fleet is divided by.
  const byKey = useMemo(() => {
    const keys = new Map<string, number>();
    for (const one of items) {
      const { key, value } = splitTag(one.tag);
      if (value !== undefined) keys.set(key, (keys.get(key) ?? 0) + 1);
    }
    return [...keys.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10);
  }, [items]);

  const shape: Segment[] = [
    { label: t("Plain"), value: loaded ? plain : undefined, tone: "neutral" },
    { label: t("Key and value"), value: loaded ? items.length - plain : undefined, tone: "info" },
  ];

  if (catalogue.error) return <Problem>{String(catalogue.error)}</Problem>;

  return (
    <>
      {renaming && <RenameTag tags={items} onClose={() => setRenaming(false)} />}
      <Board screen={TAGS_SCREEN} catalogue={TAGS} drawn={{
        count: (
          <Kpi
            icon="hosts"
            label={t("Tags")}
            value={loaded ? items.length : null}
            note={t("on the hosts you may read")}
          />
        ),
        assignments: (
          <Kpi
            icon="bulk"
            label={t("Assignments")}
            value={loaded ? assignments : null}
            // A host carrying three tags is counted three times here; it is
            // the number of labels written, not of hosts labelled.
            note={t("a host with three tags is counted three times")}
          />
        ),
        keyed: (
          <Kpi
            icon="overview"
            label={t("Keys in use")}
            value={loaded ? new Set(items.map((one) => splitTag(one.tag).key)).size : null}
            note={t("the words the fleet is divided by")}
          />
        ),
        shape: (
          <Card title={t("How the tags are written")} note={t("A plain word, or a key with a value after it.")}>
            <Band segments={shape} testId="tag-shape" />
          </Card>
        ),
        keys: (
          <Card title={t("By key")} note={t("The keys with the most values.")}>
            {!loaded
              ? <Empty>{t("Reading the catalogue…")}</Empty>
              : byKey.length === 0
                ? <Empty>{t("No tag carries a value.")}</Empty>
                : <Bars items={byKey.map(([key, n]) => ({ label: <code>{key}</code>, value: n }))} />}
          </Card>
        ),
        list: (
          <Card
            title={t("Tags")}
            note={loaded ? t("{shown} of {total} tags", { shown: shown.length, total: items.length }) : undefined}
            tools={canRename && (
              <button type="button" onClick={() => setRenaming(true)} disabled={items.length === 0} data-testid="rename-a-tag">
                {t("Rename a tag…")}
              </button>
            )}
            flush
          >
            <Toolbar>
              <Find value={search} onChange={setSearch} placeholder={t("Find a tag")} testId="tag-search" />
            </Toolbar>
            <Table
              rows={shown}
              keyOf={(one) => one.tag}
              rowTestId={(one) => `tag-${one.tag}`}
              empty={catalogue.isLoading
                ? t("Reading the catalogue…")
                : items.length === 0
                  ? t("No host you may read carries a tag. A tag is written on the host page.")
                  : t("No tag matches this.")}
              columns={[
                // The tag's own name is the way to what carries it; there is
                // no record behind a tag other than those hosts.
                { key: "tag", head: t("Tag"), tight: true, cell: (one) => (
                  <Link to={hostsWithTag(one.tag)} title={t("the hosts carrying this tag")}>{one.tag}</Link>
                ) },
                { key: "key", head: t("Key"), tight: true, minor: true, cell: (one) => (
                  <code>{splitTag(one.tag).key}</code>
                ) },
                { key: "value", head: t("Value"), tight: true, minor: true, cell: (one) => {
                  const { value } = splitTag(one.tag);
                  return value === undefined
                    ? <span className="fl-faint" title={t("a plain tag, written without a value")}>—</span>
                    : <code>{value}</code>;
                } },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.hosts },
              ]}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * Renaming one tag on every host that carries it.
 *
 * This is a dialog and not a panel on purpose: it reaches every host at
 * once and it is kept in the trail with its reason, which is exactly what
 * a decision is. The sentence says what it does not do either - a
 * selector naming the old spelling goes on naming it and matches nothing.
 */
function RenameTag({ tags, onClose }: { tags: TagCount[]; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [from, setFrom] = useState(tags.length === 1 ? tags[0].tag : "");
  const [to, setTo] = useState("");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const chosen = tags.find((one) => one.tag === from);

  const rename = useMutation({
    mutationFn: () => api.post<RenameResult>("/api/v1/tags/rename", { from, to: to.trim(), reason: reason.trim() }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ["tags"] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["host"] });
      toast.success(t("{from} renamed to {to} on {n} hosts.", { from: result.from, to: result.to, n: result.hosts }), {
        link: { to: hostsWithTag(result.to), label: t("the hosts carrying this tag") },
      });
      onClose();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "tag_not_found") {
        setMessage(t("No host you may change carries this tag any more; the catalogue is being read again."));
        void queryClient.invalidateQueries({ queryKey: ["tags"] });
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const target = to.trim();
  const named = validTagName(target);
  const ready = Boolean(chosen) && named && target !== from && reason.trim().length >= TAG_REASON_MIN_LENGTH;

  return (
    <Modal
      title={t("Rename a tag on every host carrying it")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={rename.isPending}>{t("Cancel")}</button>
          <button
            type="button"
            disabled={!ready || rename.isPending}
            onClick={() => { setMessage(""); rename.mutate(); }}
            data-testid="tag-rename"
          >
            {rename.isPending ? t("Renaming…") : t("Rename")}
          </button>
        </>
      }
    >
      <Fields>
        <Field label={t("Tag")} wide>
          <select value={from} onChange={(event) => { setFrom(event.target.value); setMessage(""); }} data-testid="tag-from">
            <option value="">{t("choose a tag…")}</option>
            {tags.map((one) => <option key={one.tag} value={one.tag}>{one.tag}</option>)}
          </select>
        </Field>
        <Field
          label={t("New name")}
          wide
          hint={named || !target
            ? t("key or key=value, lower-case key; a host already carrying the new name ends up with it once.")
            : t("Not a tag: key or key=value, lower-case key.")}
        >
          <input
            className="fl-mono"
            value={to}
            onChange={(event) => setTo(event.target.value)}
            aria-invalid={Boolean(target) && !named}
            data-testid="tag-to"
          />
        </Field>
        <Field
          label={t("Reason (kept in the audit trail)")}
          wide
          hint={t("At least {n} characters; the button opens when they are there.", { n: TAG_REASON_MIN_LENGTH })}
        >
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={t("unifying the spelling, ticket number")}
            data-testid="tag-reason"
          />
        </Field>
      </Fields>
      {chosen && named && target !== from && (
        <Note>
          {t("Every host you may change that carries {from} — {n} of the hosts you may read — gets {to} instead, in one step. Selectors, groups and campaign schedules naming the old tag go on naming it and match nothing until they are changed.",
            { from, to: target, n: chosen.hosts })}
        </Note>
      )}
      {message && <Problem>{message}</Problem>}
    </Modal>
  );
}

export const TAGS_SCREEN = "next_tags";

export const TAGS: BoardEntry[] = [
  { key: "count", title: "Tags", width: 4, height: 2 },
  { key: "assignments", title: "Assignments", width: 4, height: 2 },
  { key: "keyed", title: "Keys in use", width: 4, height: 2 },
  { key: "shape", title: "How the tags are written", width: 6, height: 3 },
  { key: "keys", title: "By key", width: 6, height: 3 },
  { key: "list", title: "Tags", width: 12, height: 7 },
];
