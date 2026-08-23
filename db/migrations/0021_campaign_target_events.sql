-- Powiadomienia o zmianie stanu celu kampanii.
--
-- Zadania mialy swoj wyzwalacz, cele kampanii nie. Operator patrzacy na
-- kampanie widzial "pending" przez caly czas jej trwania i dopiero gotowy
-- wynik - a to jest raport po fakcie, nie kontrola nad rolloutem.
--
-- Cel kampanii nie jest zadaniem: przechodzi przez wlasne stany (running,
-- rebooting, verifying), ktorych zadna operacja nie odzwierciedla. Dlatego
-- ma wlasne powiadomienie, a nie doklejenie do istniejacego.
create or replace function flotestro_powiadom_o_celu() returns trigger
language plpgsql as $$
begin
    perform pg_notify('flotestro_kampanie',
        new.campaign_id::text || ' ' || new.state);
    return null;
end;
$$;

create trigger campaign_targets_powiadomienie
    after insert or update of state on campaign_targets
    for each row execute function flotestro_powiadom_o_celu();
