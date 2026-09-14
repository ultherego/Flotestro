-- What the agent says about itself in its Hello beyond the version
-- (agent.proto, message Hello).
--
-- The build commit names the sources of the binary, which the version
-- does not once a package was rebuilt. The protocol range is what the
-- agent speaks, oldest to newest; the gateway judges compatibility by the
-- overlap with its own range before it consults the table of releases,
-- so a release the table has not heard of is still judged right. The
-- configuration fingerprint is the digest of the effective agent.yaml and
-- the schema version is what the file on disk declares: a host on the
-- environment variables of the old flow reports a schema of zero and no
-- fingerprint, which the panel shows as a legacy configuration.
--
-- Every column stays null for a host whose agent predates the report:
-- an unknown build is not an empty one, and a host that reported nothing
-- is not a host on the legacy configuration.
alter table hosts
    add column if not exists agent_build_commit    text,
    add column if not exists agent_protocol_min    integer,
    add column if not exists agent_protocol_max    integer,
    add column if not exists config_fingerprint    text,
    add column if not exists config_schema_version integer;
