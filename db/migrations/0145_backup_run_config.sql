-- Which configuration a backup run actually used.
--
-- A definition is keyed by (host, name) and a change of it keeps that key, so
-- the repository, the paths or the tool can all move while the name stays. The
-- runs are read back by definition and kind, so the proof of a successful copy
-- went on being attributed to the definition after it had been pointed at a
-- different repository: the readiness of a host was answered out of a copy that
-- no longer exists where the definition now looks.
--
-- The run records the fingerprint of the configuration it ran with, and the
-- readiness asks for a run of the configuration the definition carries now.
-- Null on the rows that are already there: they were recorded before this
-- column existed, and a null reads as "unknown" rather than as a match.
alter table backup_runs
    add column if not exists config_sha256 text;

comment on column backup_runs.config_sha256 is
    'The fingerprint of the definition this run used: tool, repository, paths, excludes and runbook. Null for runs recorded before the column existed.';

create index if not exists backup_runs_config_idx
    on backup_runs (host_id, definition, kind, config_sha256, recorded_at desc);

-- The definition carries the fingerprint of what it does now, so the join that
-- asks "is there a run of this configuration" is one comparison and not a
-- recomputation in every reader.
alter table backup_definitions
    add column if not exists config_sha256 text;

comment on column backup_definitions.config_sha256 is
    'The fingerprint of what this definition does now. A run with another one is evidence about a configuration this definition no longer has.';
