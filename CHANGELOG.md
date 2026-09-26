# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [semantic versioning](https://semver.org/). Dates are the
day the tag was published.

## [0.62.0] - 2026-09-26

### Added

- A `migrate` service in the container deployment, behind a profile and depended
  on by nothing, so the schema is not reshaped by the login that serves the
  fleet. The machinery was already there - its own DSN, `SET ROLE` with a
  refusal when the migrator turns out to be a superuser, an advisory lock, a
  digest per applied migration - and no deployment used any of it, while the
  guide said the panel migrates itself before it listens.
- `FLOTESTRO_DATABASE_MODE` says whether the database is the one the deployment
  starts or one somebody else runs, instead of the deployment inferring it from
  whether a secrets file happened to exist yet. On `external` the panel holds
  the DSN to `sslmode=verify-full` and `target_session_attrs=read-write` and
  refuses it otherwise; a laboratory can set one variable to get past both,
  which is one visible way round rather than several invisible ones. No refusal
  carries the DSN, because it holds the password. A preflight asks the database
  what it is - a standby, the extensions, the rights - before the panel settles
  on it.
- A second control plane is written down: a warm standby on the same image and
  the same secrets, its state directory restored from the pair the backup takes,
  its own gateway identifier, and stopped. Not a second active instance - two
  state directories against one database mean two fleet authorities and two
  secret-store keys for one installation, which the panel already refuses to
  start into. The refusal existed and the topology it implies did not.
- The pipeline checks that the protocol and the schema keep the promise of
  working one release apart: `buf breaking` compares the protocol with the
  newest release tag rather than with the branch it is pushing to, a release
  records the migrations it contains, and the upgrade job writes rows under the
  old version and reads them back under the new one.
- The OpenAPI document describes the body of eleven more orders - the five whose
  whole body is the reason they were placed, the team register, a host's move
  between teams, an issued token and the two role bindings - with the role
  vocabulary taken from the code rather than restated. The 56 orders still
  described as an unconstrained object are listed in a test that fails when a
  route is added to them, so the count can only fall.

### Changed

- A signed request is carried out once. The helper's replay store held one bit
  per nonce, and a repeat of a nonce by the same task in the same life of the
  process was answered "carry on" - so the same signed order could be carried
  out as often as it was asked for, and the only thing between an order and a
  second execution was the agent's own journal, on the unprivileged side of the
  boundary the helper exists to defend. The store now keeps the answer of the
  first attempt against the request it answered, and a repeat receives that
  answer instead of being performed again.
- The commit of a decommission is proven. Messages from a host to the panel are
  signed so a relay can carry the host's word without speaking for it; messages
  from the panel carried no sequence, no epoch and no signature, and the worst
  of what a relay could write was the order that makes the agent ask the helper
  to remove the host's identity, its journal and its service. The helper had
  classified that request as a read, so no capability bound it either.
- A restore is bound to the copies the operator chose. The helper answers a plan
  request with a fingerprint only when the order names the kind of plan it
  wants - a plan of a copy, against the repository and the definition - and the
  panel's button asked for a bare read of the repository, which is why the
  binding had been unreachable rather than wrong.
- Patching a vulnerability sends each host the packages it is affected in and no
  others. The page built one order out of the union of every affected host's
  packages, and a package manager refuses an upgrade of something that is not
  installed, so the order failed on the hosts that needed the least. There is
  one order per set of packages now, largest group first, and the page says how
  many orders a patch takes and why more than one.

- The root helper refuses a request it holds no rule for comparing with the
  order the capability binds. Every kind of request that changes a host now has
  such a rule - the network, resolver and firewall changes, the sshd, kernel,
  time and protection changes, the container, Compose, domain, keytab, repair,
  restart and shutdown orders - and a kind added later without one is refused
  rather than carried out on the strength of a signature. Three of the rules
  bind less than they could, deliberately: the rollback of an unverified sysctl
  change sends the host's previous readings under the capability of the order
  that made it, so the keys are bound and the values are not; the management
  address and port are what the agent knows about the channel it answers on;
  and the one-time password of a domain enrollment is minted after the
  capability is signed.
- A host can be told beforehand which panel may enroll it. Until now the helper
  verified its very first trust bundle with a key carried inside that bundle, so
  whoever reached its socket first owned the host from then on. The pin names the
  whole SHA-256 of the panel's signing key - the short identifier is eight bytes,
  which is not enough to settle who owns a machine - and the panel prints its
  fingerprints when it starts, two while a key rotation is in the air. Written
  with `flotestro-agentctl helper-trust pin` or by the Ansible role;
  `capabilities.bootstrap` stays `tofu` so an installation made before this keeps
  working.
- The agent's resident-memory budget is 36 MiB rather than 30. The two numbers
  behind it never agreed: the runtime is capped at 20 MiB and the resident pages
  of the binary add about 11 MiB, so an agent using its whole allowance sat over
  the old budget and passed only by not using it. The agent has grown -
  containers, Compose, network layers, vulnerability assessment, built-in
  monitoring - and the budget follows what it costs.
- A first installation of the agent package now writes
  `/etc/flotestro/helper.yaml` with `capabilities.mode: enforce`, so the root
  helper carries out a change only against the panel's signed capability for
  exactly that change. An upgrade does not write it: switching a running fleet
  is the operator's decision, and an agent from before the capability would
  stop working the moment the helper refused it.
- The capability now binds the target of five more orders: a signal to a
  process (the pid, the signal and the incarnation), the host's own name, a
  declared container, network or volume, a repository, a backup definition and
  a certificate deployment.

### Fixed

- An instance whose database has become a standby leaves the rotation. The start
  refused a standby outright, but a failover under a running panel left the
  instance alive and ready while every change it was handed failed on its own,
  and a load balancer went on sending it work. Readiness asks the question now,
  and the instance comes back by itself when the database is a writer again.
- A relayed message's sequence is claimed together with the work it carries.
  The number was spent in a transaction of its own before the message was
  applied, so anything in between - a database hiccup, the gateway going down, a
  failure in the work - left the number spent and the work undone; the relay
  then carried the message again, as it is meant to, and the panel read the
  number as one it had consumed and dropped it. A job result, an inventory or a
  task acknowledgement disappeared with no word anywhere.
- The changes to a host's identity are serialised. The agent daemon, the relay
  daemon and an operator running `agentctl` or `relayctl` all write into one
  directory, with no lock anywhere but the package manager's, and two at once
  were enough to lose the identity: the symlink naming the generation in force
  moved through one shared temporary name, and the clean every commit ends with
  removed every directory under the staging prefix, including another writer's.
- `ignore_inhibitors` on a restart never reached the host: the task envelope had
  no such field, so the panel dropped what the operator had asked for and the
  host respected the inhibitors anyway.
- A message of a durable class that the relay's spool would not take was
  forwarded as though it had been kept, with no copy behind it, and the relay
  went on reporting itself healthy. The session now ends with
  `resource_exhausted`, so the agent keeps the message instead of being told it
  was delivered.
- The webhook consumer held a transaction open across its delivery, so a
  receiver taking its whole fifteen seconds held the oldest transaction in the
  database for as long. And because the cursor moved only on success, one event
  the receiver will never accept stopped the whole trail at its own identifier
  for ever; after a bounded number of attempts on that event alone it is set
  aside whole and the trail goes on.
- The maintenance pass of the monitoring store and the retention sweep of the
  panel ran on every replica at once, so two replicas computed the same
  quarter-hours from the same readings and the retention of one deleted beneath
  the rollup of the other.
- Audit events that could not be written were logged and otherwise invisible;
  they are counted now, so a trail with holes in it can be alerted on.
- Retiring a secret ran its two statements outside any transaction, so a failure
  between them left a retired secret whose leases were still live - one nobody
  may be issued that hosts could still redeem. Two rotations at once computed
  the same next version and one was refused by the key.
- A change to a secret, a backup definition or a notification channel and the
  audit entry recording it now commit together.
- The monitoring settings write put the new settings in force in the process
  before the transaction committed, so a failed commit left that replica
  sweeping by a retention nobody had stored.
- Saving a backup definition from the panel wrote the whole definition back
  while the form showed nine of its seventeen fields, so changing one path
  cleared the retention, the pruning, the tags, the note and the tool's
  environment. The form has an edit mode that opens filled, and an empty
  password field now means "unchanged".
- A notification channel whose credential could not be sealed was removed
  best-effort with the error discarded, so a channel nothing backed could be
  left on record silently; and a change whose credential did not follow left the
  channel enabled, signing under one that no longer matched its configuration.
  Both now name what was left behind, and such a channel is switched off.
- The tests of the root helper wrote the registry of managed paths to
  `/var/lib/flotestro-helper`, which exists on a host that has the package and
  not on a build runner.
- A reading that landed while its quarter-hour was being recomputed had its
  mark swallowed by the pass that had already claimed the bucket, so the
  reading never reached the fifteen-minute series — a relay draining its spool
  lost the readings it was carrying.
- A second cancel of the same job was recorded and never delivered, and the
  panel then failed the job on its own timeout without ever asking the host.
  The cancel acknowledgement is also fenced now, like every other settlement.
- `schema_migrations` records the digest of what was applied, so a migration
  edited after it ran somewhere cannot describe two schemas under one label.
- A restore target was checked by name and then resolved again by the tool
  that unpacks as root, so anybody who could write a directory on the path
  could point it elsewhere in between.
- A firewalld zone change had none of the rollback and connectivity proof a
  rule change has, although firewalld keeps an established connection alive
  across a reload — so a change that locked the host out reported success. And
  the management-channel guard compared one port with one port, so removing a
  service took every port it stands for, including 443.
- A compose plan stood still for the whole operation's timeout when the
  registry would not answer, instead of falling back to the digest the host
  already held.
- The start checked only the active secrets key, so a key that live secret
  versions were sealed with and the provider no longer held surfaced at the
  first read of that secret rather than at the start.
- The host page could order an agent upgrade by version alone, and the whole
  digest-and-signer verification on the host sits behind "if a digest was
  given". The form now carries the checksum and the fall-back version.
- A webhook consumer that an installation stopped running kept its cursor and
  pinned the retention of the durable trail for ever.
- Every replica downloaded every vulnerability feed and rewrote every host's
  findings; the pass now runs under a lease, like the alert evaluator.
- The container guide names the two database facts an external installation
  needs: a pooler in transaction mode breaks the panel silently, and the
  migration switches existed in no document.
- A fleet authority activated on one replica left every other replica signing
  with the retired one and rejecting the agents that had renewed against the
  new one. Each instance now follows the record, and one that cannot catch up
  reports itself unready instead of handing out certificates nobody trusts.
- A compliance check rested on a read stamped in the panel's future: a host
  whose clock runs ahead was assessed against a month-old picture and reported
  compliant, because the age test can never fire on a negative age.
- The accounts module swallowed the helper's error, so a host whose account
  list could not be read reported accounts with no keys and no groups.
- One notification event fanned out to two channels carried the same
  identifier to the receiver, which then dropped the second as a repeat.
- A backup that left unreadable files behind, or whose retention failed, was
  recorded as a full success and kept the definition green.
- Daily partitions were only created ahead of today, so a panel that was down
  longer than its margin came back with days missing behind it and spooled
  readings for those days had nowhere to land.
- The agent-session sweep was unbounded: the first run on an aged installation
  was one transaction over the whole backlog.
- The vulnerability feed digest ignored the CVE identifiers, so a vendor that
  added one to an existing advisory was not noticed.
- NetworkManager was asked only about `ipv4.dns`, so an IPv6 resolver was
  invisible, and one the operator set was written into the IPv4 key where
  nmcli refuses it.
- Every write to the host's registry of managed files discarded its error, and
  every read of it turned a failure into an empty list. A file rewritten from
  the secret store whose registry update was lost went on publishing the
  digest of secret-derived content.
- A failed time change deleted the drop-in it could not read instead of
  restoring it.
- A relay renewal whose answer was lost left the relay holding a certificate
  the panel no longer knew, and the renewal that could have fixed it refuses an
  unknown certificate — so a whole site stayed down until somebody enrolled the
  relay by hand. The replaced certificate is kept and still recognised until
  the relay arrives with the new one.
- Retiring a certificate authority counted the hosts resting on it and never
  the relays, which are signed by the same authority.
- The agent's journal wrote without flushing, and pruned the markers of tasks
  nobody had resolved, so an agent down for longer than a day came back having
  forgotten that an outcome was unknown — and carried the change out twice.
- The audit retention sweep is now the privileged path rather than the polite
  one, and refuses a retention that is not positive.
- `certificate.deploy` now requires the plan the helper already computes; the
  panel plans on the host and shows what would be replaced.
- An idempotency key already used on a host for a different order returned the
  first task with 200 OK, telling the caller an order had gone through that
  never existed.
- A restart never asked logind what it would interrupt, although a shutdown
  did, and the panel's override checkbox governed only the shutdown.
- A stable container tag could be published unsigned, with a warning, when a
  run received no OIDC identity.
- The release signing job carried its key and passphrase in the environment of
  every step, and the passphrase travelled on gpg's command line.

## [0.61.0] - 2026-09-23

### Added

- `packages.install` and `packages.upgrade` must now carry the hash of an
  approved plan. Nine operations declared that they needed one and nothing
  asked for it: the panel sent the binding because the panel is well behaved,
  while an API caller could order a package change that resolved to whatever
  the host happened to see at the moment it ran. The check sits where an order
  becomes a job, so the panel, the API, a campaign and a remediation plan are
  all held to it, and a caller that forgets is answered with
  `plan_binding_missing` rather than a failure further in.
- Units that exist on a host but systemd has never loaded are listed, with
  their runtime state reported as unknown. A service installed and switched
  off used to be invisible, so an operator could not tell "this host does not
  have it" from "it is here and stopped".
- The count of messages journald suppressed at source, reported apart from the
  lines the view itself could not carry. A rate-limited unit used to produce a
  view that said nothing was dropped.
- `SECURITY.md`, `CONTRIBUTING.md`, this file, and `.editorconfig`.
- Both mount operations bind to a plan computed on the host. What a mount
  point already holds is the whole question — a mount hides it, an unmount
  takes it away — and the panel now plans both before it offers either.
- A blocked package says which kind of block it is: a database fault a repair
  fixes, or an update nothing classifies. An agent from before the field
  names no kind, which is read as the database fault every block used to be.
- `FLOTESTRO_NOTIFY_ALLOW` declares the networks a notification channel may
  reach, for an installation whose receivers sit on its own network.

### Changed

- The repository is laid out by what each directory holds: `docker/` and
  `ansible/` in place of `deploy/`, beside `packaging/`. The panel image and
  the compose files move with it, so the published quick-start URL is now
  `main/docker/compose.yaml`.
- A release candidate is given the version each package format sorts
  correctly: `0.61.0~rc1` for apt, release `0.rc1` for rpm, `0.61.0rc1` for
  pacman. The packaging layer would not have built one at all before.

### Fixed

- A notification channel could be pointed at the control plane's own
  loopback, at a cloud metadata service or at the fleet network, and the panel
  would fetch it: the shape of a server-side request forgery. Every delivery
  is dialled through a guard that judges the address actually resolved, and a
  redirect may only go to the receiver's own host.
- A webhook with no signing secret is refused where it is written and where it
  would be sent. An HMAC computed with an empty key is a signature only in
  shape, and the panel no longer offers to clear a stored secret.
- A security-only plan on dnf silently left out every update no advisory
  covers — a package from a repository that publishes none — and reported the
  host patched. Those updates now stay in the plan, named, with the reason,
  and a host whose advisories cannot be read is refused rather than planned
  from half an answer.
- Adopting a cron entry removed the file it was found in, taking every other
  line of that file with it. The file is removed only when the adopted entry
  is the whole of it.
- The helper mounted by running `mount <target>`, which reads `/etc/fstab`:
  an entry written on the host decided what got mounted, not the order.
- Adding an SSH key to an account that is already in a privileged group
  granted root while needing only the key permission. The host's inventory is
  asked what the account is, and an account it has not reported is refused
  rather than treated as ordinary.
- A mount verified against the mount point and the filesystem type but never
  the source, so a filesystem mounted at the right place from the wrong device
  passed.
- An upgrade plan on apt simulated a different transaction from the one that
  runs, and never read the removals at all: the branch that would have seen
  them sat behind a parse of the install line, so no upgrade plan ever carried
  a removal and the protected-package guard was empty by construction.
- The "for" window of an alert rule was counted from the timestamps of the
  samples rather than from the readings, so a dip across a missed evaluation
  pass read as an unbroken run and the alert fired on a window the condition
  had not held through.
- A host whose clock runs slow was treated as silent: freshness was judged by
  the moment the host said it took the reading, so every rule saw a permanent
  gap while host_offline said the same host was fine.
- The agent handed its free pages back at most once every five minutes, so the
  size reported to the fleet budget was the peak of the last large read rather
  than the size it keeps.
- The container image built the panel with npm lifecycle scripts enabled, and
  a backup could pair a database dump with a state archive the key material had
  moved out from under.
- The root helper's capability bound the target of an order but not what the
  order would do to it: a capability issued for writing one reviewed line into
  a file authorised writing anything into that path, with any mode and owner,
  and a capability for one key on an account authorised any key. Both now bind
  the content, the permissions and the key list.
- A cancel that arrived while a task was on the wire settled the job outright,
  so the panel reported "canceled" for a change the host went on to carry out.
  Such a job now carries an unknown outcome and says so.
- A campaign's authorisation scope was narrowed to the targets the panel could
  read, so a host the store would not answer for silently dropped out of the
  scope — and out of the two-person rule.
- A network change verified as applied without the gateway or the DNS servers
  ever being read back: an order of `method: auto` carrying both would pass on
  a DHCP lease alone.
- An install plan on dnf read a metadata cache the refresh never wrote, so a
  package added to a repository since that cache was filled did not exist as
  far as the planner was concerned, however many times a refresh was asked
  for.
- `lvm.extend` accepted any growth rather than the amount ordered, and
  `filesystem.resize` fell back to the volume's size when the mount reported
  none — so a resize that never ran could verify against the extend before it.
- A silence started while a notification waited in backoff is now honoured:
  suppression was decided once, when the row was written, and never asked
  again.
- A missing verification block is no longer read as agreement.
- System families nothing reads packages from — SUSE, Alpine, Rocky and the
  rest — are named unsupported instead of being reported as a feed that has
  not arrived yet.
- The alert history export stopped at five hundred rows without saying so, and
  the firing board had no bound at all.
- A relay renewed its certificate against the first gateway in its list and no
  other, so a single gateway down across the renewal window expired the
  certificate of a site whose data path was working.

## [0.60.5] - 2026-09-20

The first release that published. Everything between 0.60.0 and here was the
release pipeline itself being made to work; the product changed very little
across those five tags.

### Fixed

- The signing job is told which repository it releases to. Without it the
  artefacts could not be attached — and, less visibly, the guard against
  publishing a tag twice read `gh`'s failure as "no release yet" and passed by
  failing.

## [0.60.4] - 2026-09-20

### Fixed

- The repository script resolves its directories before it changes into one.
  `repo-add` runs from inside the architecture directory and was handed paths
  built from a relative repository directory, which stopped resolving there.

## [0.60.3] - 2026-09-20

### Fixed

- The signing job installs `makepkg` for the shell libraries `repo-add` loads
  at its first line.

## [0.60.2] - 2026-09-20

### Fixed

- The build job installs `pacman` beside `makepkg`. makepkg resolves it while
  reading its own configuration, long before it looks at a PKGBUILD, and
  exits through a generic trap when it is missing — so the failure named
  nothing.

## [0.60.1] - 2026-09-20

### Fixed

- The rpm specs define `%{_unitdir}`, `%{_sharedstatedir}` and the `%systemd_*`
  scriptlets when the build host does not. They ship in a Fedora package the
  release runners do not carry, and an undefined scriptlet macro would have
  installed as its own literal name — a package that built perfectly and
  failed to remove on a customer's host.

## [0.60.0] - 2026-09-19

The first tag. It did not build.

[Unreleased]: https://github.com/ultherego/Flotestro/compare/v0.61.0...HEAD
[0.61.0]: https://github.com/ultherego/Flotestro/compare/v0.60.5...v0.61.0
[0.60.5]: https://github.com/ultherego/Flotestro/compare/v0.60.4...v0.60.5
[0.60.4]: https://github.com/ultherego/Flotestro/compare/v0.60.3...v0.60.4
[0.60.3]: https://github.com/ultherego/Flotestro/compare/v0.60.2...v0.60.3
[0.60.2]: https://github.com/ultherego/Flotestro/compare/v0.60.1...v0.60.2
[0.60.1]: https://github.com/ultherego/Flotestro/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/ultherego/Flotestro/releases/tag/v0.60.0
