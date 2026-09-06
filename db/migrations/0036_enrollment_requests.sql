-- Enrollment przestaje byc samym tokenem.
--
-- Token jest sekretem autoryzujacym jedna probe, ale panel potrzebuje
-- trwalego rekordu oczekujacej instalacji: kto ja zamowil, w jakim celu,
-- czym sie skonczyla i czy nadal wolno jej uzyc. Sam skrot tokenu nie
-- odpowiada na zadne z tych pytan.
do $$
begin
    if exists (select 1 from information_schema.tables
               where table_name = 'enrollment_tokens') then
        alter table enrollment_tokens rename to enrollment_requests;
    end if;
end $$;

alter table enrollment_requests
    -- Cel blokuje ciche re-enrollment: "nowy host" i "wymiana tozsamosci
    -- istniejacego hosta" to dwie rozne decyzje i wymagaja dwoch roznych
    -- zamowien.
    add column if not exists purpose             text,
    -- Zwiazanie z konkretna maszyna i z konkretnym hostem. Przy automatyzacji
    -- i przy odzyskiwaniu tozsamosci token nie moze pasowac do czegokolwiek.
    add column if not exists expected_machine_id text,
    -- Zamowienie bez hosta, ktorego dotyczy, nie ma sensu: kasujemy je razem
    -- z hostem. Zapis o tym, ktory host powstal, zostaje - to historia, a nie
    -- zaleznosc.
    add column if not exists expected_host_id    uuid references hosts (id) on delete cascade,
    -- Status jest dla operatora i audytu, nigdy podstawa autoryzacji.
    add column if not exists status              text,
    add column if not exists enrolled_host_id    uuid references hosts (id) on delete set null,
    add column if not exists updated_at          timestamptz not null default now();

update enrollment_requests set purpose = case when kind = 'relay' then 'relay' else 'new' end
    where purpose is null;
update enrollment_requests set status = case
        when revoked_at is not null then 'revoked'
        when uses >= max_uses       then 'enrolled'
        when expires_at < now()     then 'expired'
        else 'pending'
    end
    where status is null;

alter table enrollment_requests alter column purpose set not null;
alter table enrollment_requests alter column purpose set default 'new';
alter table enrollment_requests alter column status set not null;
alter table enrollment_requests alter column status set default 'pending';

do $$
begin
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_purpose_check') then
        alter table enrollment_requests add constraint enrollment_requests_purpose_check
            check (purpose in ('new', 'replace_identity', 'relay'));
    end if;
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_status_check') then
        alter table enrollment_requests add constraint enrollment_requests_status_check
            check (status in ('pending', 'enrolled', 'expired', 'revoked', 'failed'));
    end if;
    -- Wymiana tozsamosci bez wskazania hosta byla by tokenem, ktory pasuje do
    -- kazdego - a to jest dokladnie to, przed czym cel ma chronic.
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_recovery_check') then
        alter table enrollment_requests add constraint enrollment_requests_recovery_check
            check ((purpose = 'replace_identity') = (expected_host_id is not null));
    end if;
    -- Rodzaj tozsamosci i cel musza sie zgadzac: relay nie rejestruje sie
    -- zamowieniem hosta ani odwrotnie.
    if not exists (select 1 from pg_constraint where conname = 'enrollment_requests_kind_check') then
        alter table enrollment_requests add constraint enrollment_requests_kind_check
            check ((kind = 'relay') = (purpose = 'relay'));
    end if;
end $$;

-- Proba enrollmentu jest zapisem tego, co juz zostalo wydane.
--
-- Bez niej utrata odpowiedzi w sieci konczy sie hostem bez tozsamosci
-- i tokenem, ktory jest juz zuzyty: serwer zapisal hosta i wystawil
-- certyfikat, a agent nigdy go nie zobaczyl. Powtorzona proba z tym samym
-- identyfikatorem i tym samym CSR ma dostac ten sam certyfikat.
create table if not exists enrollment_attempts (
    request_id         uuid        not null references enrollment_requests (id) on delete cascade,
    client_request_id  uuid        not null,
    csr_sha256         bytea       not null check (octet_length(csr_sha256) = 32),
    machine_id         text        not null,
    host_id            uuid        references hosts (id) on delete set null,
    certificate_pem    bytea,
    ca_bundle_pem      bytea,
    certificate_serial text,
    completed_at       timestamptz,
    created_at         timestamptz not null default now(),
    primary key (request_id, client_request_id)
);

create unique index if not exists enrollment_attempts_csr_idx
    on enrollment_attempts (request_id, csr_sha256);
