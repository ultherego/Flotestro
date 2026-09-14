-- The states the campaigns document names and the engine did not have.
--
-- Campaign: completed_with_issues for a campaign that finished under its
-- threshold with hosts that failed or ended unknown - such a campaign said
-- "completed" until now, and a report that reads the same for a clean
-- rollout and one with a third of the fleet failed is not a report; expired
-- for plans that passed their time limit before any host started - until
-- now only a target carried the plan_stale code, host by host, once the
-- campaign tried; plan_failed for a planning phase that ended with no host
-- to run on, which used to be a pause with a reason nobody could resume out
-- of; canceling for a cancel ordered while hosts are still carrying their
-- tasks, until they settle - the campaign said "canceled" while hosts kept
-- running, and a terminal state with work under it is a lie the report was
-- written from.
alter table campaigns drop constraint if exists campaigns_state_check;
alter table campaigns add constraint campaigns_state_check
    check (state in ('planning', 'planned', 'awaiting_approval', 'canary', 'manual_gate',
                     'running', 'paused', 'canceling',
                     'completed', 'completed_with_issues', 'failed', 'plan_failed',
                     'expired', 'canceled'));

-- Target: dispatched for a task handed over that the agent has not started
-- yet (the agent answers a delivery in stages since 0071); awaiting_lock for
-- a task the agent holds while a resource of the host is busy, with the
-- blocker; no_change for a host whose plan found nothing to do - a terminal
-- success without a mutation, which a report must count apart from a
-- change that landed; unknown for a task that ended without a result - the
-- session broke, or the agent came back after a restart with the operation
-- half done. Unknown is not a failure of the change and not a success
-- either: the host has to be read before anything is ordered again, and the
-- threshold counts it as a failure because it is not a success.
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'queued_offline', 'ineligible',
                     'excluded', 'dispatched', 'awaiting_lock', 'running', 'rebooting', 'verifying',
                     'succeeded', 'no_change', 'failed', 'unknown', 'skipped', 'canceled'));

-- The report is written with every terminal transition, the new ones
-- included.
alter table campaign_reports drop constraint if exists campaign_reports_state_check;
alter table campaign_reports add constraint campaign_reports_state_check
    check (state in ('completed', 'completed_with_issues', 'failed', 'plan_failed',
                     'expired', 'canceled'));
