-- What the host's root helper does with a signed capability, as the agent says at
-- its Hello: observe, prefer or enforce. Empty means a helper that has not said -
-- an agent from before the capability, or one whose helper did not answer - and
-- that is not the same as observe.
alter table hosts add column if not exists helper_capability_mode      text;
alter table hosts add column if not exists helper_capability_supported boolean;

comment on column hosts.helper_capability_mode is
    'What the root helper does with a capability the panel signed: observe, prefer or enforce; null for a helper that has not said.';
comment on column hosts.helper_capability_supported is
    'Whether the agent forwards a signed capability to its helper at all; null for an agent that has not said.';
