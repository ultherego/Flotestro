# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [semantic versioning](https://semver.org/). Dates are the
day the tag was published.

## [Unreleased]

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

### Changed

- The repository is laid out by what each directory holds: `docker/` and
  `ansible/` in place of `deploy/`, beside `packaging/`. The panel image and
  the compose files move with it, so the published quick-start URL is now
  `main/docker/compose.yaml`.
- A release candidate is given the version each package format sorts
  correctly: `0.61.0~rc1` for apt, release `0.rc1` for rpm, `0.61.0rc1` for
  pacman. The packaging layer would not have built one at all before.

### Fixed

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

[Unreleased]: https://github.com/ultherego/Flotestro/compare/v0.60.5...HEAD
[0.60.5]: https://github.com/ultherego/Flotestro/compare/v0.60.4...v0.60.5
[0.60.4]: https://github.com/ultherego/Flotestro/compare/v0.60.3...v0.60.4
[0.60.3]: https://github.com/ultherego/Flotestro/compare/v0.60.2...v0.60.3
[0.60.2]: https://github.com/ultherego/Flotestro/compare/v0.60.1...v0.60.2
[0.60.1]: https://github.com/ultherego/Flotestro/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/ultherego/Flotestro/releases/tag/v0.60.0
