-- Budzety hierarchiczne: pojemnosc floty, a nie kolizja na hoscie.
--
-- Blokada zasobu odpowiada, czy dwie operacje sie wykluczaja. Budzet odpowiada,
-- czy system ma pojemnosc, zeby uruchomic kolejna. To sa dwa rozne pytania:
-- limit pieciu hostow w kampanii nie chroni repozytorium przed setka rownoleglych
-- pobran, a mutex pakietow na hoscie nie mowi nic o obciazeniu lokalizacji.
create table if not exists budget_limits (
    -- Klucz jest scisly ('global:mutations') albo wzorcem z gwiazdka
    -- ('site:*:packages'). Wzorzec opisuje polityke domyslna dla lokalizacji,
    -- ktorej nikt jeszcze nie opisal osobno.
    key        text        primary key,
    capacity   int         not null check (capacity > 0),
    note       text        not null default '',
    updated_at timestamptz not null default now()
);

comment on table budget_limits is
    'Pojemnosc jednego budzetu. Brak wiersza znaczy budzet nieskonfigurowany, a nie zerowy.';

-- Dzierzawa tokenow. Ma wlasciciela i termin, bo awaria orkiestratora nie moze
-- trwale zmniejszyc pojemnosci floty: wygasla dzierzawa przestaje sie liczyc.
create table if not exists budget_leases (
    key         text        not null,
    owner       text        not null,
    -- Roszczacy jest jednostka sprawiedliwosci: kampania, a nie pojedynczy host.
    -- Bez tego jedna duza kampania zabralaby wszystkie wolne tokeny.
    claimant    text        not null,
    weight      int         not null check (weight > 0),
    acquired_at timestamptz not null default now(),
    lease_until timestamptz not null,
    primary key (key, owner)
);

create index if not exists budget_leases_key_expiry on budget_leases (key, lease_until);
create index if not exists budget_leases_owner on budget_leases (owner);

comment on table budget_leases is
    'Przyznane tokeny. Wygasla dzierzawa nie liczy sie do zajetosci.';

-- Oczekiwanie na tokeny. Zapisane, bo bez niego nie da sie policzyc udzialu:
-- sprawiedliwy podzial musi znac takze tych, ktorzy jeszcze nic nie dostali.
-- Czas oczekiwania jest jednoczesnie podstawa awansu: kto czeka dlugo,
-- przestaje byc ograniczany udzialem.
create table if not exists budget_waiters (
    key      text        not null,
    claimant text        not null,
    class    text        not null,
    since    timestamptz not null default now(),
    seen_at  timestamptz not null default now(),
    primary key (key, claimant)
);

comment on table budget_waiters is
    'Kto czeka na pojemnosc. Sluzy udzialowi i awansowi po czasie oczekiwania.';

-- Host, ktory czeka na tokeny, nie zajmuje slotu wykonania. Stan jest osobny,
-- zeby operator widzial roznice miedzy "jeszcze nie ruszyl" a "nie ma miejsca".
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'running', 'rebooting',
                     'verifying', 'succeeded', 'failed', 'skipped', 'canceled'));

-- Wartosci wyjsciowe z dokumentu. Wzorce dotycza kazdej lokalizacji, ktorej
-- nikt nie opisal osobno; instalacja moze je nadpisac wierszem scislym.
insert into budget_limits (key, capacity, note) values
    ('global:mutations',   50,  'jednoczesne mutacje w calej flocie'),
    ('global:reads',       200, 'jednoczesne odczyty w calej flocie'),
    ('site:*:packages',    5,   'transakcje pakietowe w jednej lokalizacji'),
    ('site:*:reboot',      2,   'restarty w jednej lokalizacji'),
    ('site:*:network',     1,   'zmiany sieci w jednej lokalizacji'),
    ('site:*:storage',     2,   'zmiany przestrzeni dyskowej w jednej lokalizacji'),
    ('site:*:backup',      2,   'operacje na repozytorium kopii'),
    ('site:*:units',       10,  'zmiany jednostek w jednej lokalizacji')
on conflict (key) do nothing;
