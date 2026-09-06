-- Epoka sesji rozstrzyga, ktora sesja hosta jest ta wlasciwa.
--
-- Host laczy sie do jednej bramy naraz, ale przy przelaczeniu miedzy bramami
-- stara sesja moze jeszcze zyc: druga brama nie wie o pierwszej, a stream
-- HTTP/2 zerwany po stronie hosta bywa widziany przez serwer z opoznieniem.
-- Bez rozstrzygniecia obie bramy uwazalyby sie za wlasciwe i to samo zadanie
-- pojechaloby dwa razy.
--
-- Numer rosnie w obrebie hosta, wiec porownanie jest lokalne i nie wymaga
-- zegara, ktory na dwoch maszynach i tak nie jest ten sam.
alter table agent_sessions add column epoch bigint not null default 0;

-- Wypelnienie historii: kolejnosc rozpoczecia jest tu jedyna prawda, jaka
-- mamy, i wystarczy - liczy sie tylko to, ze nowsza sesja ma wyzszy numer.
with numeracja as (
    select id, row_number() over (partition by host_id order by started_at, id) as numer
    from agent_sessions
)
update agent_sessions set epoch = numeracja.numer
from numeracja where agent_sessions.id = numeracja.id;

create index agent_sessions_epoch_idx on agent_sessions (host_id, epoch desc);
