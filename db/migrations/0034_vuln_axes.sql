-- Trzy osie naprawy zamiast jednego slowa, pochodzenie pakietu i osobny cykl
-- ustalen producenta.
--
-- Jedno slowo "naprawa" obiecywalo wiecej, niz panel sprawdzil: "dostepna"
-- znaczylo tylko tyle, ze producent gdzies wydal nowsza wersje. Czy ta wersja
-- lezy w repozytorium tego hosta i czy transakcja przejdzie, to sa dwa inne
-- pytania - i odpowiada na nie co innego.
alter table vuln_findings drop column if exists remediation;

alter table vuln_findings
    -- Co wydal producent. Odpowiada advisory.
    add column if not exists vendor_fix           text not null default 'unknown',
    -- Czy ta wersja jest widoczna w repozytoriach hosta. Odpowiadaja metadane
    -- repozytoriow - i tylko dla tych hostow, dla ktorych je mamy.
    add column if not exists repository_candidate text not null default 'unknown',
    -- Czy da sie ja teraz zainstalowac. Odpowiada wylacznie plan pakietowy:
    -- tylko on widzi wstrzymania, wykluczenia i konflikty modulow.
    add column if not exists transaction_state    text not null default 'unknown',
    -- Wersja naprawde porownana z ustaleniem i to, skad ona pochodzi. Debian
    -- prowadzi bezpieczenstwo po pakiecie zrodlowym, a wersja binarna bywa
    -- inna: przebudowa dokleja sufiks i wychodzi wyzsza od zrodlowej przy tym
    -- samym kodzie.
    add column if not exists comparison_version   text not null default '',
    add column if not exists comparison_basis     text not null default '',
    -- Czyj jest pakiet. Bez tego pakiet z obcego repozytorium liczylby sie
    -- jako objety ustaleniami producenta dystrybucji.
    add column if not exists package_origin       text not null default '',
    -- Odcisk zestawu ustalen, ktory rozstrzygnal. Zestaw zmienia sie takze
    -- wtedy, gdy na hoscie nie zmienil sie ani jeden pakiet.
    add column if not exists advisory_digest      text not null default '';

do $$
begin
    if exists (select 1 from information_schema.columns
               where table_name = 'vuln_host_state' and column_name = 'affected_fixable') then
        alter table vuln_host_state rename column affected_fixable to affected_with_vendor_fix;
    end if;
end $$;

alter table vuln_host_state
    add column if not exists advisory_digest text not null default '',
    -- Cztery liczniki zamiast jednego: jedna podatnosc dotyka kilku pakietow,
    -- jedno advisory niesie kilka CVE, a "1354 znalezisk" nie mowi, ile to
    -- naprawde roznych spraw do zamkniecia.
    add column if not exists unique_cves       int not null default 0,
    add column if not exists unique_advisories int not null default 0,
    add column if not exists affected_packages int not null default 0,
    -- Powod, dla ktorego nie ma ustalen producenta. Blad odczytu metadanych
    -- nie moze wygladac jak host bez ustalen.
    add column if not exists advisories_reason text not null default '';

-- Pochodzenie pakietu: APT nie zapisuje producenta przy pakiecie, wiec bierze
-- sie ono z repozytorium, z ktorego przyszla zainstalowana wersja.
alter table host_packages
    add column if not exists origin       text not null default '',
    add column if not exists origin_class text not null default '';

-- Stan ustalen producenta znanych hostowi.
--
-- Osobny od stanu listy pakietow, bo to osobne zrodlo i osobny cykl: producent
-- wydaje poprawki takze wtedy, gdy na hoscie nie zmienil sie ani jeden pakiet.
-- Bez tego panel odswiezalby ustalenia dopiero przy zmianie listy - czyli
-- czasem nigdy.
create table if not exists host_advisory_state (
    host_id            uuid        primary key references hosts(id) on delete cascade,
    digest             text        not null default '',
    advisory_count     int         not null default 0,
    collected_at       timestamptz,
    job_id             uuid        references jobs(id) on delete set null,
    unavailable_reason text        not null default ''
);
