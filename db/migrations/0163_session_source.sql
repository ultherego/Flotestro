-- Where a browser session came from is recorded, not inferred.
--
-- The password rules asked "does the session's AMR hold pwd?", and a session
-- of the identity provider can hold it too: an identity provider that
-- authenticated the person with a password says so in the same claim. A local
-- password then renewed such a session's authentication time over the ACR the
-- provider had given it, and a session that never typed the local password
-- was held to the rule about replacing it.
--
-- 'password' is a session made by the password door of this panel, 'provider' a
-- session made through the identity provider. Anything not known to be the
-- first is the second: the rules this column serves are refusals.
alter table web_sessions
    add column auth_source text not null default 'provider'
        check (auth_source in ('password', 'provider'));

-- A session of the password door is the one with no provider's tokens, no groups
-- of a provider, and the one method the door writes. A live session this
-- matches loses nothing at the upgrade; one that does not match is treated as the
-- provider's, which can only be asked to sign in again.
update web_sessions set auth_source = 'password'
 where amr = array['pwd']::text[]
   and refresh_token is null and id_token is null
   and groups = array[]::text[];
