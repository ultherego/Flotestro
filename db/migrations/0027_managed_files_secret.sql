-- A file whose content comes from the secret store.
--
-- The panel then keeps neither the content nor its digest: the digest of a
-- short value is a hint, and the store is not to leave hints outside itself.
-- The desired state is the secret name and version - and that is exactly what the operator compares.
--
-- In exchange content drift detection on the panel side is lost: the panel
-- knows which secret version was deployed, but not whether somebody swapped the file on the host.
-- That is a deliberate cost of this property.
alter table managed_files
    add column if not exists desired_secret         text,
    add column if not exists desired_secret_version int;

alter table managed_files alter column desired_sha256 drop not null;

alter table managed_file_history alter column sha256 drop not null;
alter table managed_file_history
    add column if not exists secret_name    text,
    add column if not exists secret_version int;
