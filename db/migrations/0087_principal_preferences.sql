-- The preferences of an identity: how one person likes the panel.
--
-- The theme, the language, the time zone the times are read in, the page
-- size of the lists and the page the panel opens on are the operator's,
-- not the fleet's: they follow the person to the next browser and the
-- next workstation rather than staying in the localStorage of the one
-- they happened to sit at. One row per identity, written whole by the
-- identity itself; an identity without a row is on the panel's defaults.
create table if not exists principal_preferences (
    principal_id uuid        primary key references principals (id) on delete cascade,
    -- An IANA zone name, or empty for the browser's own zone.
    time_zone    text        not null default '',
    -- Rows per page of the lists; zero means the panel's default.
    page_size    int         not null default 0 check (page_size >= 0 and page_size <= 500),
    -- The path the panel opens on after signing in; empty for the dashboard.
    landing_page text        not null default '',
    -- The interface language and the colour theme, by their codes; empty
    -- means the browser decides, as it does for an identity without a row.
    language     text        not null default '',
    theme        text        not null default '',
    updated_at   timestamptz not null default now()
);

comment on table principal_preferences is
    'How one identity likes the panel: zone, page size, landing page, language and theme. Missing row: the defaults.';
