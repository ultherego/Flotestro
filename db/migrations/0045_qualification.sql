-- A host that cannot carry out the operation stays in the campaign snapshot.
--
-- Until now hosts in a maintenance window vanished from the snapshot quietly,
-- and hosts without the required adapter entered it and ended with an error at
-- execution. Both answers were untrue: the first hid a decision, the second
-- called a missing capability a failure. An incapable host is now in the
-- snapshot, closed at once, with a given reason - and visible next to those that started.
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'ineligible',
                     'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
