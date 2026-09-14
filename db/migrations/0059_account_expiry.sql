-- The expiry date of a local account.
--
-- The panel can now set and clear the expiry of an account, so the
-- observation has to carry it: an operator who set a date is to see it
-- next to the account, and a date set by hand on the host is to be seen
-- as well. The date is kept the way the shadow record holds it, a calendar
-- day without a time zone; null means no expiry or a record the agent
-- could not read - the difference is in unavailable_reason.
alter table host_local_accounts add column if not exists expires_at text;

comment on column host_local_accounts.expires_at is
    'The expiry date of the account as YYYY-MM-DD from the shadow record; null means no expiry or an unread record.';
