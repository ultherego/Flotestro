-- The idempotency key of an enrollment order.
--
-- An automation that orders a token for a machine and loses the answer
-- must be able to ask again without minting a second token for the same
-- machine. The key is chosen by the caller and unique per creator: a
-- repeat returns the order that already exists - without the token, which
-- is shown once.
alter table enrollment_requests add column if not exists idempotency_key text;

create unique index if not exists enrollment_requests_idempotency_idx
    on enrollment_requests (created_by, idempotency_key) where idempotency_key is not null;
