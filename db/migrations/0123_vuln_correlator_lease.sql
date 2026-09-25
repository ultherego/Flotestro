-- The table already holds one row per kind of background pass, held by at most
-- one instance. The vulnerability correlator was not among them: every replica
-- downloaded and parsed every feed every half hour - close to a million
-- findings per Red Hat release, by the code's own note - and then rewrote the
-- findings of each host, so whichever transaction committed last won regardless
-- of which had read the fresher inputs.
--
-- The table is the panel's background-pass leases now, not the monitoring ones
-- alone, and the correlator takes one of them.
comment on table monitoring_leases is
    'The leases of the panel''s background passes; one row per kind of pass, held by at most one control-plane instance at a time.';

insert into monitoring_leases (name) values ('vuln_correlator')
on conflict (name) do nothing;
