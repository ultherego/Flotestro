-- The cadence a rule expects, the gap it tolerates and what it makes of a
-- gap that is wider (security remediation, chapter 12.3).
--
-- Until now every rule was judged against one hard-coded hole in the readings -
-- twice the sampling interval - and a gap wider than that was silently ignored:
-- the episode was neither advanced nor cleared and nobody was told. That is a
-- defensible default and a very poor policy for a rule whose whole point is
-- that the host keeps answering. A disk filling up is news; a disk that stopped
-- reporting how full it is, is also news, and the panel said nothing.
--
-- A rule now declares how often it expects a reading of its metric, how wide a
-- hole still counts as one continuous run of readings, and which of alert,
-- unknown or ignore applies when the readings stop for longer than that.
--
-- The defaults are exactly what the code did before: the sampling interval, two
-- of them, and ignore. A rule written before this migration therefore behaves
-- as it did, and a panel of the previous release - which names its columns in
-- every insert and update of alert_rules - keeps writing rules that behave that
-- way too.
alter table alert_rules
    add column if not exists expected_cadence_seconds integer not null default 60,
    add column if not exists max_gap_seconds          integer not null default 120,
    add column if not exists no_data_policy           text    not null default 'ignore';

comment on column alert_rules.expected_cadence_seconds is
    'How often the rule expects a reading of its metric; never below the interval the agents sample at.';
comment on column alert_rules.max_gap_seconds is
    'The widest hole in the readings that still counts as one continuous run of them, so a "for" window is not filled by silence.';
comment on column alert_rules.no_data_policy is
    'What the evaluator does when the readings stop for longer than max_gap_seconds: alert, unknown or ignore.';

-- The table refuses what the panel refuses, so a repair script or a direct
-- write cannot leave a rule the evaluator would read as a gap after every
-- reading that arrives on time.
alter table alert_rules drop constraint if exists alert_rules_cadence_range;
alter table alert_rules add constraint alert_rules_cadence_range
    check (expected_cadence_seconds >= 60 and expected_cadence_seconds <= 86400);

alter table alert_rules drop constraint if exists alert_rules_gap_covers_cadence;
alter table alert_rules add constraint alert_rules_gap_covers_cadence
    check (max_gap_seconds >= expected_cadence_seconds and max_gap_seconds <= 86400);

alter table alert_rules drop constraint if exists alert_rules_no_data_policy_known;
alter table alert_rules add constraint alert_rules_no_data_policy_known
    check (no_data_policy in ('alert', 'unknown', 'ignore'));

-- The fourth state of an episode. no_data is not "resolved": the condition may
-- well still hold, and saying it ended because the host went quiet is the one
-- thing a monitoring panel must never do. It is not "firing" either, because
-- the value on the row is no longer current.
--
-- There is deliberately no 'error' state. The chapter names one on the
-- evaluator's in-memory RuleState, where it belongs: the cases that would carry
-- it - a selector that does not resolve, a metric the panel cannot compute - are
-- facts about a rule, not about a rule on a host, and writing one row per host
-- for them would put ten thousand episodes on the board for one broken
-- selector. A state nothing ever writes is a lie in the schema, so it is not
-- added until something writes it.
alter table alerts drop constraint if exists alerts_state_check;
alter table alerts add constraint alerts_state_check
    check (state in ('pending', 'firing', 'no_data', 'resolved'));

-- The policy the episode was opened under, copied onto the row like the rule's
-- name, metric and severity: the trail has to keep saying why somebody was told
-- after the rule was changed, and the trigger below reads it.
alter table alerts add column if not exists no_data_policy text;

comment on column alerts.no_data_policy is
    'The no-data policy of the rule when this episode was written; null for an episode written before the policies existed.';

-- The trail of the alerts, with the gap in it. A no-data episode reaches the
-- notification queue only under the alert policy: unknown says "the panel does
-- not know", which belongs on the screen and not in somebody's night.
create or replace function flotestro_alert_event() returns trigger
language plpgsql as $$
declare
    host_name text;
    event     text;
    policy    text := coalesce(new.no_data_policy, 'ignore');
begin
    if new.state = 'pending' then
        return null;
    end if;
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    if new.state = 'no_data' then
        if policy <> 'alert' then
            return null;
        end if;
        event := 'alert.no_data';
    elsif new.state = 'firing' then
        event := 'alert.fired';
    else
        -- An alert resolved straight from pending never fired, so there is
        -- nothing to announce the end of; neither has a gap nobody was told of.
        if tg_op <> 'UPDATE' or old.state not in ('firing', 'no_data') then
            return null;
        end if;
        if old.state = 'no_data' and new.fired_at is null and policy <> 'alert' then
            return null;
        end if;
        event := 'alert.resolved';
    end if;
    select hostname into host_name from hosts where id = new.host_id;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('alert', new.id, event,
            jsonb_build_object(
                'rule_id',   new.rule_id,
                'rule_name', new.rule_name,
                'metric',    new.metric,
                'severity',  new.severity,
                'host_id',   new.host_id,
                'hostname',  coalesce(host_name, ''),
                'value',     new.value,
                'detail',    new.detail,
                'state',     new.state,
                'no_data_policy', policy,
                'started_at', new.started_at,
                'fired_at',  new.fired_at,
                'resolved_at', new.resolved_at));
    return null;
end;
$$;
