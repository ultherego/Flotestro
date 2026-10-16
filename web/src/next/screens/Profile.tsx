import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import { COMMON_TIME_ZONES, usePreferences, validTimeZone } from "../../lib/preferences";
import { LOCALES, useLocale } from "../../i18n";
import { SCALES } from "../../lib/scale";
import { THEMES } from "../../lib/theme";
import { useLook } from "../look";
import { relativeTime, absoluteTime } from "../../lib/format";
import type { Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Card, Fact, Facts, Field, Fields, Pill, Problem, Seg, Table, Tag, Tags,
} from "../kit";

/**
 * Everything the person at the screen sets for themselves, in one place.
 *
 * Two kinds of thing live here and they are kept apart on purpose. What
 * is kept on the server under the person's identity - the language, the
 * theme, the zone times are read in, how long a page is - follows them to
 * another browser. What is this browser's - the size of the text - stays
 * here, because it answers to this screen and no other.
 */

type Session = { id: string; created_at: string; last_seen_at?: string; user_agent?: string; address?: string; current?: boolean };

export function Profile() {
  const t = useT();
  const { preferences, loaded, save, saving } = usePreferences();
  const { locale, setLocale } = useLocale();
  const { theme, setTheme, scale, setScale } = useLook();
  const [zone, setZone] = useState(preferences.time_zone);
  const [pageSize, setPageSize] = useState(preferences.page_size ? String(preferences.page_size) : "");
  const [landing, setLanding] = useState(preferences.landing_page);
  const [problem, setProblem] = useState("");
  const [saved, setSaved] = useState(false);

  // The fields start from what the server stored, once it has answered.
  useEffect(() => {
    if (!loaded) return;
    setZone(preferences.time_zone);
    setPageSize(preferences.page_size ? String(preferences.page_size) : "");
    setLanding(preferences.landing_page);
  }, [loaded, preferences.time_zone, preferences.page_size, preferences.landing_page]);

  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const sessions = useQuery({
    queryKey: ["my-sessions"],
    queryFn: () => api.get<Collection<Session>>("/api/v1/me/sessions"),
    retry: false,
  });

  const store = async () => {
    setProblem("");
    setSaved(false);
    const size = pageSize.trim() === "" ? 0 : Number(pageSize);
    if (!validTimeZone(zone.trim())) {
      setProblem(t("The browser does not know that time zone."));
      return;
    }
    if (!Number.isFinite(size) || size < 0 || size > 500) {
      setProblem(t("A page holds between 1 and 500 rows."));
      return;
    }
    try {
      await save({ time_zone: zone.trim(), page_size: size, landing_page: landing.trim() });
      setSaved(true);
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <Board screen={PROFILE_SCREEN} catalogue={PROFILE} drawn={{
      who: (
        <Card title={t("Who you are signed in as")}>
          <Facts>
            <Fact label={t("Name")}>{me.data?.display_name || <span className="fl-faint">—</span>}</Fact>
            <Fact label={t("Subject")}><span className="fl-mono">{me.data?.subject}</span></Fact>
            <Fact label={t("Roles")}>
              <Tags>
                {(me.data?.roles ?? []).length > 0
                  ? me.data?.roles.map((role) => <Tag key={role}>{role}</Tag>)
                  : <Pill tone="unknown">{t("no roles")}</Pill>}
              </Tags>
            </Fact>
          </Facts>
        </Card>
      ),
      look: (
        <Card
          title={t("How the panel looks")}
          note={t("The theme and the language follow you to another browser; the size of the text belongs to this one.")}
        >
          <Fields>
            <Field label={t("Theme")}>
              <Seg
                label={t("Theme")}
                value={theme}
                onChange={(code) => { setTheme(code); void save({ theme: code }); }}
                options={THEMES.map((one) => ({ value: one.code, label: t(one.label) }))}
              />
            </Field>
            <Field label={t("Text size")} hint={t("Kept in this browser.")}>
              <Seg
                label={t("Text size")}
                value={scale}
                onChange={setScale}
                options={SCALES.map((one) => ({ value: one.code, label: one.label }))}
              />
            </Field>
            <Field label={t("Language")}>
              <Seg
                label={t("Language")}
                value={locale}
                onChange={(code) => { setLocale(code); void save({ language: code }); }}
                options={LOCALES.map((one) => ({ value: one.code, label: one.label }))}
              />
            </Field>
          </Fields>
        </Card>
      ),
      reading: (
        <Card
          title={t("How the panel reads to you")}
          note={t("Kept on the server under your identity.")}
          foot={saved ? t("Stored.") : undefined}
        >
          {problem && <Problem>{problem}</Problem>}
          <Fields>
            <Field label={t("Time zone")} hint={t("Empty reads every time in this browser's own zone.")}>
              <input
                list="fl-zones"
                value={zone}
                onChange={(event) => setZone(event.target.value)}
                placeholder={t("this browser's zone")}
                data-testid="zone"
              />
              <datalist id="fl-zones">
                {COMMON_TIME_ZONES.map((one) => <option key={one} value={one} />)}
              </datalist>
            </Field>
            <Field label={t("Rows per page")} hint={t("How many rows a list loads at once; empty for the panel's default, at most 500.")}>
              <input
                type="number"
                min={0}
                max={500}
                value={pageSize}
                onChange={(event) => setPageSize(event.target.value)}
                data-testid="page-size-preference"
              />
            </Field>
            <Field label={t("Landing page")} hint={t("The path the panel opens on after signing in, such as /hosts or /jobs; empty for the dashboard.")}>
              <input value={landing} onChange={(event) => setLanding(event.target.value)} placeholder="/dashboard" data-testid="landing" />
            </Field>
          </Fields>
          <Actions>
            <button type="button" onClick={store} disabled={saving} data-testid="store-preferences">
              {saving ? t("storing…") : t("Store")}
            </button>
          </Actions>
        </Card>
      ),
      sessions: (
        <Card title={t("Your sessions")} note={t("Where this identity is signed in.")} flush>
          <Table
            rows={sessions.data?.items ?? []}
            keyOf={(one) => one.id}
            loading={sessions.isLoading} empty={t("No session is recorded.")}
            columns={[
              { key: "where", head: t("From"), cell: (one) => (
                <span className="fl-mono">{one.address || <span className="fl-faint">—</span>}</span>
              ) },
              { key: "agent", head: t("Browser"), minor: true, tight: true, cell: (one) => (
                one.user_agent ? <span title={one.user_agent}>{one.user_agent}</span> : <span className="fl-faint">—</span>
              ) },
              { key: "since", head: t("Signed in"), cell: (one) => (
                <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
              ) },
              { key: "seen", head: t("Last seen"), cell: (one) => (
                one.last_seen_at
                  ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                  : <span className="fl-faint">—</span>
              ) },
              { key: "this", head: "", cell: (one) => (one.current ? <Pill tone="ok">{t("this one")}</Pill> : null) },
            ]}
          />
        </Card>
      ),
    }} />
  );
}

export const PROFILE_SCREEN = "next_profile";

export const PROFILE: BoardEntry[] = [
  { key: "who", title: "Who you are signed in as", width: 5, height: 3 },
  { key: "look", title: "How the panel looks", width: 7, height: 3 },
  { key: "reading", title: "How the panel reads to you", width: 7, height: 4 },
  { key: "sessions", title: "Your sessions", width: 5, height: 4 },
];
