-- Powiadomienia o zmianie stanu operacji.
--
-- Panel pokazywal postep dopiero po odswiezeniu strony. Operator prowadzacy
-- kampanie musi widziec, co sie dzieje, w chwili gdy sie dzieje - inaczej nie
-- ma nad nia kontroli, tylko raport po fakcie.
--
-- Powiadomienie wychodzi z bazy, a nie z kodu, ktory akurat zapisuje stan.
-- Stan operacji zmienia sie w kilku miejscach: zatwierdzenie, dostarczenie,
-- wynik agenta, anulowanie, wygasniecie i kampania. Trigger obejmuje je
-- wszystkie i nie da sie go pominac przy dopisywaniu kolejnego.
create or replace function flotestro_powiadom_o_zadaniu() returns trigger
language plpgsql as $$
begin
    -- Tresc jest krotka celowo: powiadomienie mowi, co sie zmienilo, a nie
    -- jak wyglada nowy stan. Odbiorca odczyta go z bazy, wiec nie moze
    -- zobaczyc innego stanu niz zapisany.
    perform pg_notify('flotestro_zadania',
        new.id::text || ' ' || new.state || ' ' || coalesce(new.campaign_id::text, ''));
    return null;
end;
$$;

create trigger jobs_powiadomienie
    after insert or update of state, result_status on jobs
    for each row execute function flotestro_powiadom_o_zadaniu();
