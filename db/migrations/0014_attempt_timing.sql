-- Proba zadania nie ma czasu rozpoczecia wykonania: agent go nie raportuje,
-- wiec kolumna byla pusta od poczatku. Kolumna, ktorej nikt nie wypelnia,
-- czyta sie jak "nigdy nie wystartowalo" i wprowadza w blad kazdego, kto
-- oprze na niej pomiar - wlasnie tak powstal blad w metryce opoznienia.
--
-- Obserwowalny jest czas przekazania zadania do agenta (dispatched_at) oraz
-- czas zakonczenia (finished_at) i na nich opieraja sie metryki.
alter table job_attempts drop column started_at;

-- Metryka opoznienia dostarczania czyta swieze proby po czasie przekazania.
create index job_attempts_dispatched_idx on job_attempts (dispatched_at)
    where dispatched_at is not null;
