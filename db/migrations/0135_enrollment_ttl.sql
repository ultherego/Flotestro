-- The lifetime an enrollment order was placed with.
--
-- A repeat under the same idempotency key is the same order only when it asks
-- for the same lifetime, and the deadline alone cannot say so: it moves with
-- the moment the order was placed. Orders placed before this column keep it
-- empty, and a repeat of one of them is not refused over a lifetime nobody
-- recorded.
alter table enrollment_requests add column if not exists ttl_seconds integer;
