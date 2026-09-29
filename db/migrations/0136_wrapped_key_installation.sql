-- A wrapped key says which installation it belongs to.
--
-- Until now a row said only which key encryption key it was wrapped with, and
-- that name is a keyed digest of the key material itself: two installations
-- that hold the same key produce the same name, so a row lifted out of one
-- database opened verbatim in the other. The panel could not even tell the
-- operator what had happened - a grafted row looked exactly like one of its
-- own.
--
-- The column is what the operator reads; what makes it true is that the
-- installation is bound into the associated data of the wrapping from form 2
-- on. Editing this column does not make a row belong here, it makes it stop
-- opening.
--
-- Null is a row of form 1, written before any of this. It keeps opening under
-- the associated data it was sealed with, so no installation has to re-seal
-- anything to start; a rewrap of the key encryption key carries every row over
-- to form 2.
alter table crypto_wrapped_keys add column if not exists installation_id text;

comment on column crypto_wrapped_keys.installation_id is
    'The installation this key belongs to. Null on a row of the first form, which named none. From form 2 on it is part of what the row is sealed against: a row of another installation is refused by name rather than read.';
