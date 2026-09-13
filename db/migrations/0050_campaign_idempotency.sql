-- The idempotency key of a campaign.
--
-- A pipeline or a ticketing system that orders a campaign and loses the
-- answer must be able to ask again without creating a second campaign on
-- the same fleet. The key is chosen by the caller and unique per creator:
-- a repeat returns the campaign that already exists.
alter table campaigns add column if not exists idempotency_key text;

create unique index if not exists campaigns_idempotency_idx
    on campaigns (created_by, idempotency_key) where idempotency_key is not null;
