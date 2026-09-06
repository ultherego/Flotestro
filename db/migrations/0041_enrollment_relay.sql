-- Ograniczenie zamowienia enrollmentu do jednego relaya.
--
-- W izolowanej lokalizacji host nie widzi centrali i rejestruje sie przez
-- relay. Relay jest wtedy terminatorem TLS, wiec widzi token - i to on
-- poswiadcza centrali, ze zgloszenie przyszlo z jego lokalizacji.
--
-- Bez tego ograniczenia token wyniesiony z jednej lokalizacji dzialalby
-- w kazdej innej. Wpisany relay_id znaczy: to zamowienie mozna zrealizowac
-- wylacznie przez ten relay. Puste znaczy "bez ograniczenia trasy" i tak
-- zostaje dla instalacji bez relayow.
alter table enrollment_requests add column relay_id uuid references relays (id);

create index enrollment_requests_relay_idx on enrollment_requests (relay_id)
    where relay_id is not null;
