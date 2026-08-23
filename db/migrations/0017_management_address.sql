-- Adres zarzadzania hosta.
--
-- Host moze miec wiele adresow, laczyc sie zza NAT-u albo przez relay
-- lokalizacji. Pierwszy adres z listy interfejsow nie jest adresem
-- zarzadzania i nie wolno go za taki podawac - operator potwierdzajacy
-- operacje musi widziec adres, ktory faktycznie opisuje ten host.
--
-- Zrodlo jest czescia faktu, bo dwa adresy o roznym pochodzeniu znacza co
-- innego: 'session' widzi panel na swoim koncu polaczenia, 'agent' deklaruje
-- host o sobie (jedyne wyjscie, gdy miedzy nimi stoi relay), 'manual' ustawia
-- operator. Brak adresu zostaje pusty - nieustalony adres nie jest adresem.
alter table hosts
    add column management_address             text,
    add column management_address_source      text,
    add column management_address_observed_at timestamptz;

alter table hosts add constraint hosts_management_address_source_check
    check (management_address_source is null
           or management_address_source in ('session', 'agent', 'manual'));

-- Adres bez zrodla i zrodlo bez adresu sa zapisem niepelnym.
alter table hosts add constraint hosts_management_address_complete_check
    check ((management_address is null and management_address_source is null)
           or (management_address is not null and management_address_source is not null));
