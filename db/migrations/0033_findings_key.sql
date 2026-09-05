-- Ustalenie dotyczy konkretnej wersji zainstalowanego pakietu.
--
-- Ten sam pakiet bywa zainstalowany kilka razy w roznych wersjach - tak dziala
-- jadro w rodzinie RPM: stare wersje zostaja na dysku razem z nowa. Bez wersji
-- w kluczu ustalenia dla nich nachodzily na siebie, a zapis calej oceny hosta
-- konczyl sie konfliktem klucza.
--
-- To jest tez wlasciwa odpowiedz merytoryczna: host z zalatanym i niezalatanym
-- jadrem na dysku ma niezalatane jadro - i to musi byc widoczne osobno.
alter table vuln_findings drop constraint if exists vuln_findings_pkey;

alter table vuln_findings
    add constraint vuln_findings_pkey
    primary key (host_id, provider, advisory_id, binary_package, architecture,
                 installed_version);
