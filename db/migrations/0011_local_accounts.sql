-- Konta lokalne widziane na hoscie. Tabela jest odwzorowaniem stanu hosta,
-- a nie zrodlem prawdy o kontach: prawda jest /etc/passwd na hoscie, a panel
-- jedynie pamieta ostatnia obserwacje, zeby dalo sie ja przegladac i filtrowac.
--
-- Modul jest przeznaczony dla instalacji bez katalogu. Tam, gdzie dziala
-- FreeIPA lub inny katalog, konta ludzi pochodza z katalogu i panel ich nie
-- duplikuje; kolumna source pozwala te dwa swiaty odroznic.
create table host_local_accounts (
    host_id            uuid        not null references hosts (id) on delete cascade,
    name               text        not null,
    uid                bigint      not null,
    gid                bigint      not null,
    home               text,
    shell              text,
    gecos              text,
    -- local | directory | system
    source             text        not null,
    groups             text[]      not null default '{}',
    -- NULL oznacza stan nieustalony: helper moze byc niedostepny, a wtedy
    -- "odblokowane" byloby zmyslonym faktem.
    locked             boolean,
    ssh_keys           jsonb       not null default '[]'::jsonb,
    unavailable_reason text,
    observed_at        timestamptz not null default now(),
    primary key (host_id, name)
);

create index host_local_accounts_source_idx on host_local_accounts (source, name);
-- Konta bez klucza SSH i bez blokady sa dostepne wylacznie haslem albo wcale;
-- to pierwsza rzecz, ktorej szuka audyt w instalacji bez katalogu.
create index host_local_accounts_keyless_idx on host_local_accounts (host_id)
    where source = 'local' and ssh_keys = '[]'::jsonb;
