-- The way and time of the session authentication.
--
-- The operations with the greatest impact require fresh authentication, not
-- merely holding a session. To check that, the panel must remember when the
-- provider actually authenticated the user and which level it declared.
--
-- NULL in authenticated_at means the provider gave no auth_time. That is an
-- undetermined state, not "a moment ago": a session without that knowledge
-- cannot pass the freshness check.
alter table web_sessions add column authenticated_at timestamptz;
alter table web_sessions add column acr              text;
alter table web_sessions add column amr              text[] not null default '{}';
