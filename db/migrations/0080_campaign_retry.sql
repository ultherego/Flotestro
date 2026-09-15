-- The link between a campaign and the campaign that retries its failures.
--
-- A campaign that left hosts failed or unknown is not run again as it
-- was: the hosts that succeeded hold the desired state, and ordering the
-- change on them once more is a second change nobody asked for. The retry
-- is a new campaign on exactly the hosts that did not get there, with the
-- same order and its own approval. Like the compensation link it is
-- written on the new campaign only: the original's record is what was
-- approved and what happened, and stays as it is. Its side of the link is
-- read back through this column.
alter table campaigns
    add column if not exists retries_campaign_id uuid references campaigns (id);

comment on column campaigns.retries_campaign_id is
    'The campaign whose failed hosts this one runs again, with the same order. Null for a campaign that is not a retry.';

create index if not exists campaigns_retries_idx
    on campaigns (retries_campaign_id)
    where retries_campaign_id is not null;
