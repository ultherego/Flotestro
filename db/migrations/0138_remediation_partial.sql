-- A remediation plan has a fifth state: it ran to its end over a step that
-- failed.
--
-- With stop_on_failure off the plan carries on past a failure, and the runner
-- then found no step left to run and settled the plan as "succeeded" - over a
-- host where part of the remediation had not happened. Running past a failure
-- was the operator's choice; calling the result a success was nobody's.
do $$
begin
    if exists (select 1 from pg_constraint where conname = 'remediation_plans_state_check') then
        alter table remediation_plans drop constraint remediation_plans_state_check;
    end if;
    alter table remediation_plans add constraint remediation_plans_state_check
        check (state in ('running', 'succeeded', 'failed', 'stopped', 'partial'));
end $$;
