-- The offline policy, the deadline, the manual gate and the connectivity
-- threshold of a campaign.
--
-- Until now a host that was not connected when its turn came was passed
-- over in silence and waited without end. Offline is a normal state of a
-- fleet, and every operation now says what a campaign does with such a
-- host: requires it online, leaves it out, waits for it until a deadline or
-- computes its plan again once it is back. The campaign records the policy
-- it really runs under, the moment it stops waiting, whether it stops after
-- the canary for a decision, and how many lost sessions halt it.
alter table campaigns
    add column if not exists offline_policy text not null default 'wait_until_deadline'
        check (offline_policy in ('require_online', 'skip_if_offline',
                                  'wait_until_deadline', 'replan_on_reconnect'));
-- Campaigns from before the policy waited for their hosts; they keep doing
-- so, bounded now by a deadline a day after their creation.
alter table campaigns add column if not exists deadline_at timestamptz;
update campaigns set deadline_at = created_at + interval '24 hours' where deadline_at is null;

alter table campaigns add column if not exists manual_gate boolean not null default false;
alter table campaigns add column if not exists gate_advanced_by text;
alter table campaigns add column if not exists gate_advanced_at timestamptz;
alter table campaigns
    add column if not exists connectivity_lost_absolute integer not null default 0
        check (connectivity_lost_absolute >= 0);

comment on column campaigns.offline_policy is
    'What the campaign does with a host that is not connected when its turn comes.';
comment on column campaigns.deadline_at is
    'When the campaign stops waiting for offline hosts; such hosts end skipped with offline_deadline.';
comment on column campaigns.manual_gate is
    'Whether the campaign stops after the canary until an operator advances it into the waves.';
comment on column campaigns.connectivity_lost_absolute is
    'How many hosts may lose their session mid-task before the campaign pauses; zero disables the check.';

-- The gate is a state of its own: the campaign waits for a person, like a
-- pause, and the orchestrator starts nothing in it.
alter table campaigns drop constraint if exists campaigns_state_check;
alter table campaigns add constraint campaigns_state_check
    check (state in ('planning', 'planned', 'awaiting_approval', 'canary', 'manual_gate',
                     'running', 'paused', 'completed', 'failed', 'canceled'));

-- A host queued offline takes no slot and no token; it waits for its
-- connection and goes back to the queue when the host comes back.
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'queued_offline', 'ineligible',
                     'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
