-- Korelator podatnosci.
--
-- Rozstrzyga tracker bezpieczenstwa producenta dystrybucji, a nie feed
-- upstreamowy: poprawki backportowane maja numery wersji, ktorych zaden
-- zakres z NVD nie obejmuje, wiec porownanie z nim daje falszywe alarmy
-- w jedna strone i przeoczenia w druga.
--
-- Snapshot feedu jest niezmienny i ma odcisk: ocena, ktorej nie da sie
-- powiazac z konkretnymi danymi, nie da sie ani powtorzyc, ani obronic.
create table if not exists vuln_snapshots (
    id                 uuid        primary key default gen_random_uuid(),
    provider           text        not null,
    digest             text        not null,
    -- Releases wylicza wydania objete snapshotem. To z tego bierze sie
    -- odpowiedz "tego wydania feed nie obejmuje" - inna niz "brak podatnosci".
    releases           text[]      not null default '{}',
    advisory_count     int         not null default 0,
    fetched_at         timestamptz not null default now(),
    source_modified_at timestamptz,
    etag               text        not null default '',
    -- Aktywny snapshot jest jeden na dostawce. Nieudany import nie zastepuje
    -- poprzedniego: lepiej ocenic starszymi danymi i powiedziec, ze sa
    -- starsze, niz nie ocenic wcale.
    active  boolean not null default false,
    error   text    not null default '',
    unique (provider, digest)
);

create unique index if not exists vuln_snapshots_active_idx
    on vuln_snapshots (provider) where active;

create table if not exists vuln_advisories (
    snapshot_id    uuid   not null references vuln_snapshots(id) on delete cascade,
    provider       text   not null,
    advisory_id    text   not null,
    cve_ids        text[] not null default '{}',
    distribution   text   not null,
    release        text   not null,
    -- Klucz korelacji: tracker mowi o pakiecie zrodlowym, host ma binarne.
    source_package text   not null,
    binary_package text   not null default '',
    -- Pusta wersja naprawiona oznacza podatnosc bez poprawki: pakiet jest
    -- podatny i nie ma czym tego naprawic.
    fixed_version  text   not null default '',
    status         text   not null,
    vendor_severity text  not null default '',
    title          text   not null default '',
    url            text   not null default '',
    published_at   timestamptz,
    primary key (snapshot_id, advisory_id, release, source_package, binary_package)
);

create index if not exists vuln_advisories_lookup_idx
    on vuln_advisories (snapshot_id, distribution, release, source_package);

-- Ustalenia dla hostow. Kazde niesie odcisk snapshotu i odcisk listy pakietow,
-- ktore je rozstrzygnely: bez tego nie wiadomo, czego dotyczy odpowiedz.
create table if not exists vuln_findings (
    host_id           uuid   not null references hosts(id) on delete cascade,
    provider          text   not null,
    advisory_id       text   not null,
    cve_ids           text[] not null default '{}',
    distribution      text   not null default '',
    release           text   not null default '',
    source_package    text   not null default '',
    binary_package    text   not null default '',
    architecture      text   not null default '',
    installed_version text   not null default '',
    fixed_version     text   not null default '',
    -- Trzy stany, nie dwa: "nie wiadomo" jest odpowiedzia, a nie brakiem
    -- odpowiedzi, i zawsze ma kod powodu.
    state             text   not null,
    reason_code       text   not null default '',
    remediation       text   not null default 'unknown',
    vendor_severity   text   not null default '',
    snapshot_digest   text   not null default '',
    inventory_digest  text   not null default '',
    comparator_version text  not null default '',
    evaluated_at      timestamptz not null default now(),
    primary key (host_id, provider, advisory_id, binary_package, architecture)
);

create index if not exists vuln_findings_state_idx on vuln_findings (state, vendor_severity);
create index if not exists vuln_findings_host_idx on vuln_findings (host_id, state);

-- Stan oceny hosta: czym byla rozstrzygana, kiedy i na ile pokryta.
--
-- Pokrycie jest tu rownie wazne jak liczba znalezisk. Host bez znalezisk
-- i host, ktorego feed nie obejmuje, wygladaja tak samo na liczniku - i tylko
-- ta tabela pozwala je rozroznic.
create table if not exists vuln_host_state (
    host_id          uuid        primary key references hosts(id) on delete cascade,
    distribution     text        not null default '',
    release          text        not null default '',
    provider         text        not null default '',
    snapshot_digest  text        not null default '',
    inventory_digest text        not null default '',
    packages_total   int         not null default 0,
    packages_covered int         not null default 0,
    affected         int         not null default 0,
    -- Podatnosc z poprawka i podatnosc bez poprawki prowadza do zupelnie
    -- innych decyzji: pierwsza jest do zainstalowania dzis, druga jest do
    -- oceny ryzyka. Sklejone w jedna liczbe daja sciane, ktorej nikt nie
    -- przeczyta.
    affected_fixable int         not null default 0,
    affected_no_fix  int         not null default 0,
    unknown          int         not null default 0,
    coverage_reason  text        not null default '',
    evaluated_at     timestamptz
);
