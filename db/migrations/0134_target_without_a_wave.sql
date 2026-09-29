-- A host that takes no part in a campaign belongs to no wave.
--
-- The snapshot of a campaign holds every host the selector named, the hosts
-- that will run and the hosts that were already settled when the order was
-- placed: decommissioned, ineligible for the operation, excluded by name.
-- Those settled hosts were written into wave 0, which is the canary, so
-- everything that counts the canary - the preview, the target list, the
-- report, the API - answered with the canary plus all of them. A fleet of 31
-- hosts of which 27 were decommissioned said "the canary has 28 hosts" while
-- one host was going to run, and the canary exists precisely so that number
-- can be trusted before an approval.
--
-- They take -1 instead. A sentinel rather than a null column: the wave is read
-- as an integer everywhere, it orders the rollout, and the page cursor of the
-- target list compares (wave, position) as a pair - a null there would drop
-- those rows out of the paging in silence instead of naming them.
alter table campaign_targets drop constraint if exists campaign_targets_wave_check;
alter table campaign_targets add constraint campaign_targets_wave_check check (wave >= -1);

comment on column campaign_targets.wave is
    'The wave of the rollout: 0 is the canary, then the waves in order. -1 is a host that takes no part - it was settled when the campaign was created and never runs.';

-- The rows already written. A host settled at the creation of its campaign
-- ended in the same transaction that inserted it, so its finish carries the
-- moment of its own insert; a host that turned ineligible while the campaign
-- ran settled later, had a wave of its own and keeps it.
--
-- Each of them takes a position of its own, as it does when written today: the
-- page cursor of the target list is the pair (wave, position), and rows that
-- share a pair fall off the edge of a page.
with aside as (
    select id,
           row_number() over (partition by campaign_id order by created_at, id) - 1 as place
      from campaign_targets
     where wave = 0
       and state in ('ineligible', 'excluded')
       and finished_at is not null
       and finished_at = created_at
       and started_at is null
       and job_id is null
       and plan_job_id is null
       and reboot_job_id is null
       and health_job_id is null
)
update campaign_targets t
   set wave = -1, position = aside.place
  from aside
 where aside.id = t.id;
