-- Health signals may be undetermined. Earlier the columns were NOT NULL with
-- a default of zero, so a failed read on the host was indistinguishable from
-- a real zero: a failing agent reported "zero updates" and "no failed
-- units". NULL now means an undetermined state.

alter table hosts
    alter column failed_units             drop default,
    alter column failed_units             drop not null,
    alter column pending_updates          drop default,
    alter column pending_updates          drop not null,
    alter column pending_security_updates drop default,
    alter column pending_security_updates drop not null,
    alter column reboot_required          drop default,
    alter column reboot_required          drop not null;

-- Values written by the faulty agent version come from execution errors,
-- not from host observations. They are wiped so that they do not pose as knowledge.
update hosts set
    failed_units             = null,
    pending_updates          = null,
    pending_security_updates = null,
    reboot_required          = null;

-- The index now covers only the hosts something is actually known about.
drop index if exists hosts_attention_idx;
create index hosts_attention_idx on hosts (reboot_required, failed_units)
    where reboot_required or failed_units > 0;
