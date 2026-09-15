-- The acknowledgement of an alert.
--
-- A silence switches a sensor off for a bounded time; an acknowledgement
-- says the opposite: the sensor is right, somebody has seen it and is
-- working on it. The alert keeps firing - the condition has not ended -
-- but the counts of what waits for a person leave it out, and the row
-- says who took it and what they wrote. The note is free text an operator
-- may leave on any alert, acknowledged or not: where the cause was found,
-- which change is on its way.
alter table alerts add column if not exists acknowledged_by text;
alter table alerts add column if not exists acknowledged_at timestamptz;
alter table alerts add column if not exists note text not null default '';

comment on column alerts.acknowledged_by is
    'Who took the alert; empty while it waits for somebody.';
comment on column alerts.acknowledged_at is
    'When the alert was taken; the alert keeps firing until its condition ends.';
comment on column alerts.note is
    'What the operator wrote on the alert: the cause, the change on its way.';
