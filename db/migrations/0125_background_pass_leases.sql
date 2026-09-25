-- Two passes of the panel ran on every replica at once: the maintenance pass of
-- the monitoring store - partitions, rollup, retention of the samples - and the
-- retention sweep of the panel itself. Both are the installation's work and not
-- one instance's: two replicas computed the same buckets from the same rows and
-- deleted under each other, and a third just paid for it.
insert into monitoring_leases (name) values
    ('monitoring_maintenance'),
    ('housekeeping_sweep')
on conflict (name) do nothing;
