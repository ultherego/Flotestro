-- Relaye lokalizacji. Relay obsluguje polaczenia agentow w swojej lokalizacji,
-- buforuje wyniki na czas awarii lacza i ogranicza liczbe polaczen do centrali.
--
-- Relay jest osobna granica zaufania: konczy polaczenie agenta i sam swiadczy
-- panelowi, czyj to ruch. Dlatego ma wlasna tozsamosc, wlasny certyfikat
-- i wlasny zakres - moze posredniczyc wylacznie za hosty swojej lokalizacji.
create table relays (
    id                 uuid        primary key,
    name               text        not null,
    site               text        not null,
    environment        text,
    -- Odcisk obecnego certyfikatu; rotacja podmienia go w miejscu.
    fingerprint_sha256 bytea       unique,
    serial             text,
    not_after          timestamptz,
    enrolled_at        timestamptz not null default now(),
    last_seen_at       timestamptz,
    revoked_at         timestamptz,
    revocation_reason  text,
    created_at         timestamptz not null default now()
);

create unique index relays_name_idx on relays (name);
create index relays_site_idx on relays (site) where revoked_at is null;

-- Sesja agenta moze isc przez relay. Zapis mowi, kto poswiadczyl tozsamosc
-- hosta: bez tego slad audytowy nie odroznia polaczenia bezposredniego od
-- posredniczonego, a to dwie rozne podstawy zaufania.
alter table agent_sessions add column relay_id uuid references relays (id);
create index agent_sessions_relay_idx on agent_sessions (relay_id) where relay_id is not null;

-- Token enrollmentu sluzy teraz dwom rodzajom tozsamosci.
alter table enrollment_tokens add column kind text not null default 'agent';
