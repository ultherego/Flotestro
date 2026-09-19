-- A global silence is the one that may keep back the security alerts of the
-- whole installation, so it covers all of it.
--
-- The suppression reads global before it reads the host: for a security alert
-- it looks for a silence with global set and stops at the first one. A row
-- that is both global and bound to a host or a rule would therefore blind the
-- security alerts of that host on the strength of a silence somebody wrote
-- for its disk - and writing a silence of one host is an ordinary on-call
-- right, while blinding the security channel is not. The panel refuses such a
-- request; the table refuses the row, so an older release, a repair script or
-- a direct write cannot make one either.
--
-- Every existing row has global false (the column was never settable), so the
-- constraint holds on what is already there.
alter table silences add constraint silences_global_is_not_narrowed
    check (not global or (host_id is null and rule_id is null));

comment on constraint silences_global_is_not_narrowed on silences is
    'A global silence names neither a host nor a rule: silencing one sensor is not a permission to blind the installation.';
