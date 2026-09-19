-- What the panel refused, and where it had to supply a host's clock itself
-- (security remediation, chapters 12.3 and 16.1).
--
-- Until now a refused sample left nothing behind. The gateway answered the
-- host REJECTED_TOO_OLD, wrote a line in its log and forgot it. The chart
-- of that host then showed the same thing as a host nobody ever asked to
-- report: no readings. During an incident that is the worst possible
-- answer, because the operator reads a quiet chart as a quiet machine. A
-- hole with a cause and a hole with no cause are different facts and the
-- panel has to hold both.
--
-- The shape is a counter per host, per typed code and per day of the
-- refused reading, not a row per refused sample. A relay that comes back
-- after a week drains its spool in one burst: ten thousand readings of one
-- host, every one of them past the lateness budget. A row each would put a
-- table the size of the samples themselves beside the samples, to say one
-- thing - "this host was cut off from here to here, for this reason". The
-- day is what bounds the span so two outages a month apart do not read as
-- one, and it is the same granularity the raw partitions use.
create table if not exists metric_gaps (
    host_id         uuid        not null references hosts (id) on delete cascade,
    -- The code of the refusal as the error guide lists it, never a sentence:
    -- the panel shows it, the operator looks it up, translations follow it.
    reason          text        not null,
    -- The day of the refused reading, by the moment the host claimed for it.
    day             date        not null,
    samples         bigint      not null default 0,
    -- The span the refused readings cover, so the hole can be drawn where it
    -- happened rather than where it was noticed.
    first_sample_at timestamptz not null,
    last_sample_at  timestamptz not null,
    -- When the panel last refused one, by the panel's own clock.
    last_refused_at timestamptz not null default now(),
    primary key (host_id, reason, day)
);

comment on table metric_gaps is
    'What the panel would not store, counted per host, per typed reason code and per day of the refused reading. A hole in a chart that has a row here has a cause; one that has none is a host that was simply quiet.';
comment on column metric_gaps.reason is
    'The typed code of the refusal, as internal/opspec/errors.go lists it.';
comment on column metric_gaps.first_sample_at is
    'The oldest refused reading of the day, by the moment the host claimed for it; the left edge of the hole.';

-- The chart asks for the refusals that fall inside its window.
create index if not exists metric_gaps_span_idx on metric_gaps (host_id, last_sample_at desc);

-- Where the panel supplied the moment of a reading itself.
--
-- The gateway already replaced the moment of a sample dated ahead of the
-- panel's clock, and told nobody. Chapter 16.1 asks the opposite: when the
-- gateway's time is used, the UI says so, because every point of that host
-- is then drawn at a moment the host did not choose. One row per host: the
-- skew of a clock is a property of the machine, not of a reading, and the
-- last measurement is the one worth showing.
create table if not exists metric_clock_skew (
    host_id       uuid        not null primary key references hosts (id) on delete cascade,
    -- The typed code of the substitution, for the same reason as above.
    reason        text        not null,
    -- How far the host's clock stood from the panel's on the last reading
    -- the panel restamped, in milliseconds; positive means the host is ahead.
    skew_millis   bigint      not null,
    substitutions bigint      not null default 0,
    last_at       timestamptz not null default now()
);

comment on table metric_clock_skew is
    'The hosts whose clock stood further from the panel''s than the installation allows, and whose readings the panel therefore stamped with its own time.';

-- The column has been the moment the host claimed for its newest reading,
-- which makes a host whose clock runs slow look silent while it is talking.
-- Freshness is the panel's own clock: chapter 12.3 says the host's time is
-- an observation and nothing more.
comment on column hosts.last_metrics_at is
    'When the panel last received a resource sample from the host, by the panel''s clock; empty for a host that never sent one. The moment the host claimed for that reading lives in host_metrics.at.';
