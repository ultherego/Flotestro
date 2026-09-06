-- Wzbogacenie ustalen o dane upstreamowe: CVSS i opis podatnosci.
--
-- Osobna tabela, a nie kolumny przy ustaleniu, bo to sa dane innego rodzaju
-- i innego zrodla. Producent dystrybucji rozstrzyga, czy pakiet jest podatny
-- i ktora wersja to zamyka; NVD nie ma o tym nic do powiedzenia - jego
-- zakresy wersji nie obejmuja poprawek backportowanych. Moze za to powiedziec,
-- jak grozna jest sama podatnosc, i to jest jedyne, co panel stad bierze.
create table if not exists vuln_cve_details (
    cve           text primary key,
    source        text not null,
    cvss_score    double precision,
    cvss_severity text not null default '',
    cvss_vector   text not null default '',
    cvss_version  text not null default '',
    summary       text not null default '',
    published_at  timestamptz,
    modified_at   timestamptz,
    fetched_at    timestamptz not null default now()
);

-- Stan synchronizacji: od kiedy pytac o zmiany. Bez niego kazde uruchomienie
-- panelu pobieraloby caly zbior od nowa - a to prawie czterysta tysiecy
-- wpisow i dwiescie zadan do serwisu, ktory na to patrzy.
create table if not exists vuln_enrichment_state (
    source        text primary key,
    last_modified timestamptz,
    entries       integer not null default 0,
    updated_at    timestamptz not null default now(),
    error         text not null default ''
);
