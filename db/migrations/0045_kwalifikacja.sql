-- Host, ktory nie moze wykonac operacji, zostaje w migawce kampanii.
--
-- Do tej pory hosty w oknie serwisowym znikaly z migawki po cichu, a hosty bez
-- wymaganego adaptera wchodzily do niej i konczyly sie bledem przy wykonaniu.
-- Obie odpowiedzi byly nieprawdziwe: pierwsza ukrywala decyzje, druga nazywala
-- brak zdolnosci awaria. Host niezdolny jest teraz w migawce, zamkniety od
-- razu, z podanym powodem - i widac go obok tych, ktore ruszyly.
alter table campaign_targets drop constraint if exists campaign_targets_state_check;
alter table campaign_targets add constraint campaign_targets_state_check
    check (state in ('pending', 'planning', 'awaiting_budget', 'ineligible',
                     'running', 'rebooting', 'verifying',
                     'succeeded', 'failed', 'skipped', 'canceled'));
