-- Snapshot feedu ma dwie daty, bo to dwa rozne fakty.
--
-- "Pobrano" mowi, z kiedy sa dane. "Sprawdzono" mowi, kiedy panel ostatni raz
-- upewnil sie, ze nic sie nie zmienilo. Feed, ktory zmienia sie raz na dobe,
-- byl bez tego uznawany za nieswiezy po szesciu godzinach - choc panel pytal
-- o niego co pol godziny i za kazdym razem dostawal "bez zmian".
alter table vuln_snapshots
    add column if not exists checked_at timestamptz;

update vuln_snapshots set checked_at = fetched_at where checked_at is null;
