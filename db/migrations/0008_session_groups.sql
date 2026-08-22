-- Grupy z tokenu tozsamosci sa zapamietane w sesji. Mapowanie na role liczymy
-- przy kazdym zadaniu, wiec zmiana polityki dziala bez ponownego logowania
-- uzytkownika, a zmiana czlonkostwa w katalogu przy nastepnym logowaniu.
alter table web_sessions add column groups text[] not null default '{}';
