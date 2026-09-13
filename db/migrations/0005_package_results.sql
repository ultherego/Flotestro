-- The result specific to the operation type: an update plan or a transaction
-- report. It is kept as JSONB, because the shape depends on the operation, and
-- normalising every field of every operation would make adding new modules harder.
alter table job_attempts add column result_detail jsonb;

-- A host whose package database needs repair after a failed transaction must
-- not take part in further campaigns until it is sorted out.
alter table hosts add column package_database_broken boolean not null default false;

create index hosts_package_broken_idx on hosts (package_database_broken)
    where package_database_broken;
