-- The layout of the fleet dashboard, as a setting of the installation.
--
-- The dashboard drew a fixed set of widgets in a fixed order at fixed
-- widths, decided by whoever wrote the screen. Which numbers matter and how
-- much room each deserves is a property of the fleet being run, not of the
-- panel: one installation watches campaigns all day, another watches
-- certificates and never orders a campaign.
--
-- One row, and the layout is the installation's rather than each person's.
-- That is deliberate: an operations screen people talk to each other over
-- ("look at the second tile") stops working when everyone sees a different
-- second tile, and a per-person layout would also have to be taught to
-- every new account. Whoever may write the settings decides it for all.
--
-- The widgets are held as JSON rather than as rows, because this table has
-- no business knowing what a widget is: the panel owns the catalogue of
-- them, and a key this version of the panel does not know is skipped when
-- the screen is drawn. That is what lets a panel and a record of different
-- versions meet without either refusing the other.
--
-- N-1: a replica on the previous release never reads this table, and the
-- dashboard it draws is the fixed one. Nothing here changes an existing
-- table, so a downgrade needs no undo.
create table if not exists dashboard_layout (
    singleton  boolean     primary key default true check (singleton),
    -- [{"key": "host_availability", "width": 12}, ...] in the order drawn.
    widgets    jsonb       not null,
    updated_at timestamptz not null default now(),
    updated_by text        not null default '',
    revision   bigint      not null default 1
);

comment on table dashboard_layout is
    'The widgets of the fleet dashboard, their order and their widths, for the whole installation; absent means the panel draws its own default layout.';
comment on column dashboard_layout.widgets is
    'An ordered JSON array of {key, width}. The panel owns the catalogue of keys; one it does not know is skipped rather than refused, so a record written by a newer panel still draws on an older one.';
