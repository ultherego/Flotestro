-- The boot a remediation plan started from.
--
-- A plan whose step reboots the host has to be able to tell "the host came
-- back" from "the host never went away", and the only thing that says which is
-- the boot identifier the plan began with. The runner records it and reads it
-- back; the column it reads was never created, so every read of the remediation
-- plans failed with "column boot_id_before does not exist" and the endpoint
-- answered 500. The code and the schema were written in the same change and
-- only one of them was finished.
--
-- Nullable, because a plan with no rebooting step has no boot to remember, and
-- the plans already in the table were made before this column existed.
alter table remediation_plans
    add column if not exists boot_id_before text;

comment on column remediation_plans.boot_id_before is
    'The boot the plan started from, for a step that reboots the host. Null when the plan has no such step.';
