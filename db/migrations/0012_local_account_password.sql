-- The password state of a local account. A lock and no password are two
-- different states: an account created by the panel has no password and logs
-- in with an SSH key, which does not mean the administrator cut it off.
--
-- NULL means an undetermined state, for example when the helper was unavailable.
alter table host_local_accounts add column password_set boolean;

-- An account without a password and without a key is reachable by nobody. That
-- state is worth showing: it usually means somebody revoked access halfway.
create index host_local_accounts_unreachable_idx on host_local_accounts (host_id)
    where source = 'local' and password_set is false and ssh_keys = '[]'::jsonb;
