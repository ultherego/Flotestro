-- Plany per host dla kampanii.
--
-- Dwa hosty wybrane tym samym zamowieniem prawie nigdy nie maja tego samego
-- diffu: inny zestaw pakietow, inne wersje, inne zaleznosci. Kampania, ktora
-- zatwierdza jeden payload, zatwierdza wiec zmiane, ktorej nikt nie widzial.
-- Plan powstaje osobno dla kazdego hosta, a zgoda dotyczy calego zestawu.
create table if not exists campaign_plans (
    campaign_id uuid        not null references campaigns(id) on delete cascade,
    host_id     uuid        not null references hosts(id) on delete cascade,
    plan_hash   text        not null,
    plan        jsonb       not null default '{}'::jsonb,
    computed_at timestamptz not null default now(),
    primary key (campaign_id, host_id)
);

comment on table campaign_plans is
    'Plan wyliczony na jednym hoscie. Odcisk wiaze zgode z tym wlasnie diffem.';

-- Odcisk calego zestawu planow. Wchodzi do odcisku zatwierdzenia, wiec plan
-- przeliczony na innym stanie hosta uniewaznia zgode.
alter table campaigns
    add column if not exists plan_set_hash text not null default '';

-- Zadanie planujace hosta. Osobna kolumna, bo plan i zmiana sa dwoma roznymi
-- operacjami tego samego celu.
alter table campaign_targets
    add column if not exists plan_job_id uuid references jobs(id);

-- Nowe stany: kampania i host licza plan, zanim cokolwiek sie zmieni.
alter table campaigns drop constraint if exists campaigns_state_check;
alter table campaigns add constraint campaigns_state_check
    check (state in ('planning', 'planned', 'awaiting_approval', 'canary', 'running',
                     'paused', 'completed', 'failed', 'canceled'));

alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
