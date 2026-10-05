-- Who a claimed moment was claimed for.
--
-- A schedule's order is placed under the rights of the schedule's author, and
-- editing a schedule makes the editor its author. The recovery of an unsettled
-- occurrence read the schedule again, so a schedule edited between the claim
-- and the recovery was recovered under the new author - and the campaign's
-- idempotency is (created_by, idempotency_key). The key "schedule:<id>:<moment>"
-- therefore no longer named the campaign the first attempt had placed, and the
-- recovery placed a second campaign for the same moment: the same change
-- carried out twice over the fleet, under somebody who had only edited the
-- schedule.
--
-- The moment records the author it was claimed for, and the recovery orders
-- under that author, so the key is the one that was used.
alter table schedule_occurrences
    add column if not exists claimed_by text not null default '';

comment on column schedule_occurrences.claimed_by is
    'The subject the moment was claimed for. The recovery of an unsettled moment orders under it, so the idempotency key of the order names the campaign the first attempt placed.';

-- The rows already here were claimed under the author the schedule carries
-- now: that is the value the recovery would have used for them anyway, and it
-- is written down instead of being read again later.
update schedule_occurrences o
   set claimed_by = s.created_by
  from campaign_schedules s
 where s.id = o.schedule_id
   and o.claimed_by = '';
