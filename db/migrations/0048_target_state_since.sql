-- The moment a campaign target entered its current state.
--
-- The time a target spends in a state is measured when it leaves it, and the
-- histogram of those times is what the document asks for under
-- flotestro_target_state_duration_seconds. Neither started_at nor
-- finished_at says when a host started waiting for its budget or when its
-- reboot began - only the last transition does.
alter table campaign_targets
    add column if not exists state_since timestamptz not null default now();

comment on column campaign_targets.state_since is
    'When the target entered its current state; the basis of the time-in-state measurement.';
