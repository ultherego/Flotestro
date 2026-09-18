-- The verification of a change on the attempt that made it.
--
-- Every mutating operation declares a verifier in the contract
-- (internal/opspec/verifier.go), and the host reads itself after the
-- change and compares what it finds with what the payload or the plan
-- promised. Until now that reading existed only on the wire: the agent
-- settled the result by it and the observation was gone. The operator saw
-- "failed: applied_unverified" with no way to learn which verifier had
-- looked, what it expected and what it found - and a verified change left
-- no record that anybody had looked at all.
--
-- From here the observation is kept on the attempt that produced it: the
-- verifier's name, whether the state was observed, what was expected, what
-- was found, and the reason a mismatch gives. It carries no content of a
-- file and no secret - a digest, a state word, a version - so it is stored
-- as it comes from the host.
alter table job_attempts
    add column if not exists verification jsonb;

comment on column job_attempts.verification is
    'The read of the host after the change: {verifier, verified, expected, observed, reason}. Null for an attempt that reported none - a read, an operation whose verifier the panel settles, or an agent from before the verifiers.';

-- The screens that hunt for changes nobody confirmed ask one question:
-- which attempts reported a verification that failed. A fleet's worth of
-- settled attempts must not be read to answer it.
create index if not exists job_attempts_unverified_idx
    on job_attempts (job_id)
    where verification is not null and (verification ->> 'verified') = 'false';
