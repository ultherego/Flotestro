-- Odcisk zatwierdzenia kampanii.
--
-- Zatwierdzenie ma dotyczyc dokladnie tego, co operator zobaczyl: tej samej
-- operacji, tego samego payloadu, tej samej listy hostow i tej samej polityki
-- rozwijania. Bez odcisku zgoda odnosila sie do identyfikatora kampanii,
-- a wiec takze do wszystkiego, co ktos zmienilby po drodze.
alter table campaigns
    add column if not exists approval_fingerprint text not null default '';

comment on column campaigns.approval_fingerprint is
    'Odcisk operacji, payloadu, migawki hostow i polityki rozwijania. Zatwierdzenie musi go podac.';
