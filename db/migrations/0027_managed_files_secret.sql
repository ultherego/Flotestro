-- Plik, ktorego tresc pochodzi z magazynu sekretow.
--
-- Panel nie trzyma wtedy ani tresci, ani jej odcisku: odcisk krotkiej wartosci
-- jest wskazowka, a magazyn ma nie zostawiac wskazowek poza soba. Stanem
-- docelowym jest nazwa sekretu i wersja - i to wlasnie porownuje operator.
--
-- Zamiast tego traci sie wykrywanie driftu tresci po stronie panelu: panel wie,
-- ktora wersje sekretu wdrozono, ale nie wie, czy ktos podmienil plik na hoscie.
-- To swiadomy koszt tej wlasnosci.
alter table managed_files
    add column if not exists desired_secret         text,
    add column if not exists desired_secret_version int;

alter table managed_files alter column desired_sha256 drop not null;

alter table managed_file_history alter column sha256 drop not null;
alter table managed_file_history
    add column if not exists secret_name    text,
    add column if not exists secret_version int;
