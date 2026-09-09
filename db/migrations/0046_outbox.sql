-- Trwaly slad zdarzen kampanii i jej celow.
--
-- Powiadomienia LISTEN/NOTIFY budza otwarte ekrany, ale nie sa kolejka trwala:
-- zdarzenie wyslane w chwili, gdy panel byl restartowany, nie istnieje juz
-- nigdzie. Stan koncowy da sie odczytac z tabel, ale przebieg - to, co i kiedy
-- sie stalo - znikal. Kampania bez przebiegu jest raportem po fakcie, a nie
-- kontrola nad rolloutem.
--
-- Zdarzenie powstaje w wyzwalaczu, a nie w kodzie panelu. Dzieki temu jest
-- zapisane w tej samej transakcji co zmiana stanu i nie da sie zmienic stanu
-- bez zapisania zdarzenia - takze wtedy, gdy zmiane zrobi inna instancja
-- panelu albo reczna poprawka w bazie.
create table if not exists outbox_events (
    id             bigserial   primary key,
    aggregate_type text        not null,
    aggregate_id   uuid        not null,
    event_type     text        not null,
    payload        jsonb       not null default '{}'::jsonb,
    occurred_at    timestamptz not null default now(),
    -- published_at czeka na pierwszego konsumenta spoza panelu. Dzisiaj
    -- jedynym odbiorca jest ten panel i czyta tabele wprost, wiec kolumna
    -- zostaje pusta. Jest tutaj, bo przeniesienie publikacji na broker ma nie
    -- wymagac zmiany ksztaltu zdarzen ani ich identyfikatorow.
    published_at   timestamptz
);

comment on table outbox_events is
    'Trwaly slad zmian stanu. Zapisywany w jednej transakcji ze zmiana, ktora opisuje.';

create index if not exists outbox_events_agregat
    on outbox_events (aggregate_type, aggregate_id, id);
create index if not exists outbox_events_nieopublikowane
    on outbox_events (id) where published_at is null;

-- Zdarzenia celu kampanii. Powod i komunikat sa czescia zdarzenia, bo bez nich
-- "host failed" nie mowi nic poza tym, ze cos poszlo zle.
create or replace function flotestro_zdarzenie_celu() returns trigger
language plpgsql as $$
begin
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('campaign_target', new.campaign_id, 'target.' || new.state,
            jsonb_build_object(
                'target_id',  new.id,
                'host_id',    new.host_id,
                'wave',       new.wave,
                'error_code', coalesce(new.error_code, ''),
                'message',    coalesce(new.message, ''),
                'job_id',     new.job_id));
    return null;
end;
$$;

drop trigger if exists campaign_targets_zdarzenie on campaign_targets;
create trigger campaign_targets_zdarzenie
    after insert or update of state on campaign_targets
    for each row execute function flotestro_zdarzenie_celu();

-- Zdarzenia samej kampanii: wejscie w faze, wstrzymanie, zamkniecie.
create or replace function flotestro_zdarzenie_kampanii() returns trigger
language plpgsql as $$
begin
    if tg_op = 'UPDATE' and old.state = new.state then
        return null;
    end if;
    insert into outbox_events (aggregate_type, aggregate_id, event_type, payload)
    values ('campaign', new.id, 'campaign.' || new.state,
            jsonb_build_object(
                'name',         new.name,
                'action_type',  new.action_type,
                'pause_reason', coalesce(new.pause_reason, ''),
                'approved_by',  coalesce(new.approved_by, '')));
    return null;
end;
$$;

drop trigger if exists campaigns_zdarzenie on campaigns;
create trigger campaigns_zdarzenie
    after insert or update of state on campaigns
    for each row execute function flotestro_zdarzenie_kampanii();
