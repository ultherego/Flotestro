-- Operacje niszczace dane wymagaja zgody dwoch osob.
--
-- Zasada drugiej osoby, ktora juz mamy, mowi tylko tyle, ze zlecajacy nie
-- zatwierdza sam siebie. Przy formatowaniu dysku to za malo: pomylka jednej
-- osoby, ktora akurat ma prawo zatwierdzac, kosztuje dane, ktorych nikt nie
-- odtworzy. Dlatego liczba wymaganych zgod jest cecha zadania, a nie
-- srodowiska - i zapisujemy kazda zgode osobno, z osoba i czasem.
alter table jobs
    add column if not exists required_approvals smallint not null default 1
        check (required_approvals between 1 and 3);

create table if not exists job_approvals (
    job_id      uuid        not null references jobs(id) on delete cascade,
    approver    text        not null,
    reason      text,
    approved_at timestamptz not null default now(),
    -- Ta sama osoba nie zatwierdza dwa razy: dwie zgody maja znaczyc dwie
    -- osoby, a nie dwa klikniecia.
    primary key (job_id, approver)
);

create index if not exists job_approvals_job_idx on job_approvals(job_id);
