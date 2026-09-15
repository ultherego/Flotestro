-- Scheduled and recurring campaigns.
--
-- A schedule is a campaign order kept for later: the same body POST
-- /api/v1/campaigns takes, with the moment it is to be placed and, for a
-- standing change such as the monthly patch window, a rule for the moments
-- after that. The panel orders the campaign at the moment; the campaign
-- itself is an ordinary one - it goes through every check the order goes
-- through at the door and waits for its approval like any other. The
-- schedule never runs anything by itself: it places orders.
--
-- The rule is the RRULE subset a maintenance calendar needs: a monthly
-- rule by day of the month, a weekly rule by weekdays, each at an hour
-- and a minute in the schedule's own zone. The next moment is kept on the
-- row so the loop asks one indexed question per tick and the calendar
-- reads the moments without computing them.
create table if not exists campaign_schedules (
    id               uuid primary key default gen_random_uuid(),
    name             text not null,
    -- The campaign order, in the shape POST /api/v1/campaigns reads.
    order_body       jsonb not null,
    -- The first moment. Without a recurrence it is the only one; with one
    -- it is the earliest moment the rule may name.
    start_at         timestamptz,
    -- The rule, as text: FREQ=MONTHLY;BYMONTHDAY=n;BYHOUR=h;BYMINUTE=m or
    -- FREQ=WEEKLY;BYDAY=MO,TU;BYHOUR=h;BYMINUTE=m. Null for a single moment.
    recurrence       text,
    -- The IANA zone the rule's hours are read in; the local wall clock of
    -- the site, so a window at two in the morning stays at two across a
    -- daylight-saving change.
    timezone         text not null default 'UTC',
    -- The next moment the loop places the order at; null once a single
    -- moment has passed or a rule names nothing more.
    next_run_at      timestamptz,
    last_run_at      timestamptz,
    -- The campaign the last run ordered, or null when the last run was
    -- refused; last_error then says why, in the same words the door would
    -- have answered with.
    last_campaign_id uuid references campaigns (id) on delete set null,
    last_error       text not null default '',
    created_by       text not null,
    enabled          boolean not null default true,
    -- The reason recorded with the schedule and carried into every order
    -- it places.
    reason           text not null default '',
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now()
);

comment on column campaign_schedules.order_body is
    'The campaign order as POST /api/v1/campaigns takes it; placed at every moment of the schedule under the same checks.';
comment on column campaign_schedules.created_by is
    'The subject who last wrote the order and whose rights it is placed under; read again at every run, so a right taken away stops the schedule.';

-- The loop asks for the schedules that are due; the calendar for the
-- moments in a range. Both read this index.
create index if not exists campaign_schedules_due_idx
    on campaign_schedules (next_run_at)
    where enabled and next_run_at is not null;
