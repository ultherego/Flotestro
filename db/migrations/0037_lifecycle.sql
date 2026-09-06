-- Cykl zycia hosta ma czwarty stan i wlasna pamiec powodu.
--
-- Miedzy "dziala" a "wycofany" jest chwila, w ktorej panel juz nie zleca nic
-- nowego, ale host jeszcze konczy to, co zaczal. Bez tego stanu wycofanie
-- albo urywa prace w polowie, albo pozwala zlecic kolejna.
do $$
begin
    if exists (select 1 from pg_constraint where conname = 'hosts_lifecycle_state_check') then
        alter table hosts drop constraint hosts_lifecycle_state_check;
    end if;
    alter table hosts add constraint hosts_lifecycle_state_check
        check (lifecycle_state in ('active', 'quarantined', 'retiring', 'retired'));
end $$;

alter table hosts
    -- Powod zmiany stanu jest czescia decyzji, a nie komentarzem: host
    -- w kwarantannie bez powodu jest hostem, o ktorym nikt juz nie pamieta,
    -- dlaczego zostal odciety.
    add column if not exists lifecycle_reason     text        not null default '',
    add column if not exists lifecycle_changed_at timestamptz,
    add column if not exists lifecycle_changed_by text        not null default '',
    add column if not exists retired_at           timestamptz;

create index if not exists hosts_lifecycle_idx on hosts (lifecycle_state)
    where lifecycle_state <> 'active';
