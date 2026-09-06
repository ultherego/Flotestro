-- Nazwy sieciowe relaya sa czescia jego tozsamosci, a nie tresci zadania.
--
-- Certyfikat relaya jest jedynym certyfikatem floty z rola serwerowa: agenci
-- lokalizacji weryfikuja po nim nazwe, pod ktora sie laczyli. Gdyby nazwy
-- pochodzily z zadania odnowienia, relay moglby przy kazdym odnowieniu wziac
-- nazwe cudzej uslugi i stac sie dla agentow czyms innym niz byl.
--
-- Zapis w rejestrze czyni ze zmiany nazw decyzje operatora: odnowienie
-- wystawia to, co panel ma zapisane, i nic ponadto.
alter table relays add column advertised_names text[] not null default '{}';

-- Ostatnie odnowienie mowi, czy relay w ogole utrzymuje swoja tozsamosc.
-- Certyfikat relaya zyje siedem dni; relay, ktory nie odnawial sie od
-- tygodnia, jest o krok od odciecia calej lokalizacji.
alter table relays add column renewed_at timestamptz;
