-- Sposob i czas uwierzytelnienia sesji.
--
-- Operacje o najwiekszym wplywie wymagaja swiezego uwierzytelnienia, a nie
-- samego posiadania sesji. Zeby to sprawdzic, panel musi pamietac, kiedy
-- dostawca faktycznie uwierzytelnil uzytkownika i jaki poziom zadeklarowal.
--
-- NULL w authenticated_at oznacza, ze dostawca nie podal auth_time. To stan
-- nieustalony, a nie "przed chwila": sesja bez tej wiedzy nie moze przejsc
-- kontroli swiezosci.
alter table web_sessions add column authenticated_at timestamptz;
alter table web_sessions add column acr              text;
alter table web_sessions add column amr              text[] not null default '{}';
