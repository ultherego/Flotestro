-- The link between a campaign and the campaign that compensates it.
--
-- A rollback is not a button on the finished campaign: it is a new
-- campaign with its own plans and its own approval, running the reverse
-- operation on the hosts the first one changed. Until now the two were
-- strangers - the operator knew that "Rollback of X" came after X only
-- from the name. The link is written on the compensating campaign, never
-- on the original: the original's record is what was approved and what
-- happened, and it stays as it is. Its side of the link is read back
-- through this column, and its targets receive a compensate step row
-- when the reverse change runs on their host.
--
-- The target state check gains nothing here on purpose. The document
-- names compensating and compensated as target states, but a target's
-- terminal state is the record of what the campaign did to the host, and
-- the report written from those states is immutable. Moving a failed
-- target to "compensated" would take the failure out of every count and
-- filter that reads the state - the very history the document says a
-- compensation must not erase. The compensate step row on the target
-- carries the compensation instead, with its task, its outcome and the
-- campaign it belongs to.
alter table campaigns
    add column if not exists compensates_campaign_id uuid references campaigns (id);

comment on column campaigns.compensates_campaign_id is
    'The campaign this one undoes: the reverse operation on the hosts that changed. Null for a campaign that is not a compensation.';

create index if not exists campaigns_compensates_idx
    on campaigns (compensates_campaign_id)
    where compensates_campaign_id is not null;
