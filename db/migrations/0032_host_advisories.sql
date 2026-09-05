-- Ustalenia producenta znane hostowi z metadanych jego wlasnych repozytoriow.
--
-- Dla Fedory to jest zrodlo rozstrzygajace: mowi o wersjach z tych samych
-- repozytoriow, z ktorych host bierze pakiety. Panel nie zgaduje, czy poprawka
-- jest osiagalna - host ja widzi albo nie.
--
-- Trzymamy wylacznie ustalenia bezpieczenstwa dotyczace pakietow, ktore na tym
-- hoscie naprawde sa: pelna lista wydania to tysiace pozycji, z ktorych
-- wiekszosc dotyczy rzeczy, ktorych host nie ma.
create table if not exists host_advisories (
    host_id      uuid   not null references hosts(id) on delete cascade,
    advisory_id  text   not null,
    package_name text   not null,
    architecture text   not null default '',
    -- Wersja, ktora zamyka ustalenie, w postaci EVR producenta.
    fixed_evr    text   not null default '',
    cve_ids      text[] not null default '{}',
    severity     text   not null default '',
    title        text   not null default '',
    issued_at    timestamptz,
    collected_at timestamptz not null default now(),
    primary key (host_id, advisory_id, package_name, architecture)
);

create index if not exists host_advisories_package_idx
    on host_advisories (host_id, package_name);
