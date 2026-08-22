-- Wynik wlasciwy dla typu operacji: plan aktualizacji albo raport transakcji.
-- Trzymamy go jako JSONB, bo ksztalt zalezy od operacji, a normalizowanie
-- wszystkich pol kazdej operacji utrudnialoby dodawanie nowych modulow.
alter table job_attempts add column result_detail jsonb;

-- Host, ktorego baza pakietow wymaga naprawy po nieudanej transakcji, nie moze
-- brac udzialu w kolejnych kampaniach do czasu wyjasnienia.
alter table hosts add column package_database_broken boolean not null default false;

create index hosts_package_broken_idx on hosts (package_database_broken)
    where package_database_broken;
