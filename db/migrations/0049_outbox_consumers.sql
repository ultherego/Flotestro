-- The cursors of the consumers of the durable trail.
--
-- A consumer outside the panel - a webhook, later a broker - reads the
-- trail from its own position and moves it only after a delivery succeeded.
-- The delivery is therefore at least once, the receiver deduplicates by the
-- event identifier, and a consumer that stopped shows as a growing distance
-- between its cursor and the end of the trail.
create table if not exists outbox_consumers (
    name        text        primary key,
    last_id     bigint      not null default 0,
    failures    integer     not null default 0,
    last_error  text        not null default '',
    -- next_attempt_at holds a failing consumer back: a receiver that is
    -- down is not asked again every round.
    next_attempt_at timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table outbox_consumers is
    'Where every external consumer of the durable trail has got to; moved only after a delivery.';
