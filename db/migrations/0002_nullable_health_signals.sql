-- Sygnaly zdrowia moga byc nieustalone. Wczesniej kolumny mialy NOT NULL
-- z domyslnym zerem, wiec nieudany odczyt na hoscie byl nieodrozninalny od
-- prawdziwego zera: agent w bledzie raportowal "zero aktualizacji" i "brak
-- jednostek w bledzie". NULL oznacza teraz stan nieustalony.

alter table hosts
    alter column failed_units             drop default,
    alter column failed_units             drop not null,
    alter column pending_updates          drop default,
    alter column pending_updates          drop not null,
    alter column pending_security_updates drop default,
    alter column pending_security_updates drop not null,
    alter column reboot_required          drop default,
    alter column reboot_required          drop not null;

-- Wartosci zapisane przez wadliwa wersje agenta pochodza z bledow wykonania,
-- a nie z obserwacji hosta. Kasujemy je, zeby nie udawaly wiedzy.
update hosts set
    failed_units             = null,
    pending_updates          = null,
    pending_security_updates = null,
    reboot_required          = null;

-- Indeks uwzglednia teraz tylko hosty, o ktorych faktycznie cos wiemy.
drop index if exists hosts_attention_idx;
create index hosts_attention_idx on hosts (reboot_required, failed_units)
    where reboot_required or failed_units > 0;
