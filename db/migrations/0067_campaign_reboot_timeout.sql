-- How long a campaign waits for a rebooted host.
--
-- Until now the wait was a constant of the engine: fifteen minutes from the
-- moment the host started its change, whatever the machine. A storage node
-- with a long firmware check and a container host that is back in forty
-- seconds are not waited for the same way, and a wait the approver cannot
-- read is not part of the consent. The campaign records the bound it really
-- runs under; campaigns from before the column keep the fifteen minutes.
alter table campaigns
    add column if not exists reboot_timeout_seconds integer not null default 900
        check (reboot_timeout_seconds between 60 and 7200);

comment on column campaigns.reboot_timeout_seconds is
    'How long the campaign waits for a host to come back after the reboot it ordered before the host is failed with reboot_timeout.';
