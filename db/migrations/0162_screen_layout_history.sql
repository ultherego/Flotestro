-- An arrangement that can be changed for everybody has to be undoable.
--
-- 0156 made the arrangement of a screen a row of the installation, shared by
-- everyone who opens it. 15.10 the owner asked for every panel of every tab
-- to be arrangeable, which turns that row from a rarely touched setting into
-- something an administrator moves around on an ordinary afternoon - and one
-- administrator's afternoon is every operator's screen.
--
-- Two things follow, and both are here rather than in the panel.
--
-- A change needs a reason, like every other change that reaches other
-- people; the column holds it and the audit entry repeats it. Rows written
-- before this migration have none, and an empty string is the honest answer
-- for them rather than an invented sentence.
--
-- A change needs an undo. The previous versions are kept so a screen that
-- was made worse can be put back without a database restore; the panel
-- offers the last ten. The history is keyed by the revision the main table
-- already counts, so the two cannot disagree about what came first.
alter table screen_layout
    add column if not exists reason text not null default '';

comment on column screen_layout.reason is
    'Why this arrangement was written, as the person who wrote it put it. Empty for rows written before 15.10, when the change needed no reason.';

create table if not exists screen_layout_history (
    screen     text        not null,
    revision   bigint      not null,
    widgets    jsonb       not null,
    updated_at timestamptz not null default now(),
    updated_by text        not null default '',
    reason     text        not null default '',
    primary key (screen, revision)
);

comment on table screen_layout_history is
    'What each arrangeable screen looked like before its current arrangement, newest revision first. Written when an arrangement is replaced, so a change that made a screen worse can be put back.';

-- The panel reads the newest few; nothing reads this table by date.
create index if not exists screen_layout_history_recent_idx
    on screen_layout_history (screen, revision desc);
