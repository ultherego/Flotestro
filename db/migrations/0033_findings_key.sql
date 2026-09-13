-- A finding concerns a specific version of an installed package.
--
-- The same package may be installed several times in different versions -
-- that is how the kernel works in the RPM family: old versions stay on disk
-- together with the new one. Without the version in the key the findings for
-- them overlapped, and writing the whole host assessment ended with a key conflict.
--
-- It is also the right substantive answer: a host with a patched and an
-- unpatched kernel on disk has an unpatched kernel - and that must be visible separately.
alter table vuln_findings drop constraint if exists vuln_findings_pkey;

alter table vuln_findings
    add constraint vuln_findings_pkey
    primary key (host_id, provider, advisory_id, binary_package, architecture,
                 installed_version);
