-- Stan hasla konta lokalnego. Blokada i brak hasla to dwa rozne stany:
-- konto zalozone przez panel nie ma hasla i loguje sie kluczem SSH, co nie
-- znaczy, ze zostalo odciete przez administratora.
--
-- NULL oznacza stan nieustalony, na przyklad gdy helper byl niedostepny.
alter table host_local_accounts add column password_set boolean;

-- Konto bez hasla i bez klucza jest niedostepne dla nikogo. To stan wart
-- pokazania: zwykle znaczy, ze ktos odebral dostep polowicznie.
create index host_local_accounts_unreachable_idx on host_local_accounts (host_id)
    where source = 'local' and password_set is false and ssh_keys = '[]'::jsonb;
