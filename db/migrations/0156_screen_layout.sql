-- The stored layout is per screen, not only the dashboard's.
--
-- 0155 gave the fleet dashboard an arrangement of its own. The same question
-- - which of these do I want, in what order, how wide - is asked of the
-- status board and of the settings screen, and answering it three times with
-- three tables would be three of everything: three routes, three validations
-- and three ways for them to drift apart.
--
-- So the row is keyed by the screen it belongs to. 'dashboard' is what 0155
-- stored, and the default on the column carries it over without a data step.
--
-- N-1: a replica on the previous release reads dashboard_layout by name and
-- would fail on the rename, so this is a migration to apply with the panel
-- stopped or rolled forward on every replica at once. The window is small -
-- 0155 is in no release - and the alternative, a view under the old name,
-- would outlive the reason for it.
alter table if exists dashboard_layout rename to screen_layout;

alter table screen_layout
    add column if not exists screen text not null default 'dashboard';

alter table screen_layout drop constraint if exists dashboard_layout_pkey;
alter table screen_layout drop column if exists singleton;
alter table screen_layout add primary key (screen);

alter table screen_layout
    add constraint screen_layout_screen_is_a_name
    check (screen ~ '^[a-z][a-z0-9_]{0,31}$');

comment on table screen_layout is
    'The widgets of each arrangeable screen, their order and their widths, one row per screen and shared by the whole installation; a screen with no row is drawn the way the panel ships it.';
