# The key encryption key, and moving the installation's keys into the database

## Purpose

An installation's private keys — the keys the secret store seals its values with, the
private key of the fleet CA and of a CA prepared to take over, the key that signs the root
helper's capabilities — used to live in the state directory of whichever machine happened
to run the panel. A second replica could not read what the first had sealed, a restore
needed the directory as well as the dump, and nothing said which key belonged to which
installation.

They can instead live in the database, each row sealed with a *key encryption key* (KEK)
that the deployment mounts as a secret. The rows travel with the database; the key does
not, so a copy of the dump alone opens nothing. This runbook covers generating that key,
moving the installation onto it, rotating it, moving back, and finally removing the files.

Nothing here happens by itself. The panel does not migrate at start, does not rewrap on a
schedule and never removes a key file.

## Signals

- `GET /api/v1/status`, block `crypto`: `provider` is `local-sealed` while the keys are
  files and `db-sealed` once they are rows; for `db-sealed` the block also carries `kek_id`.
- The panel logs one line at start saying where its keys come from, with the `kek_id` (never
  the key).
- A start that refuses carries one of `kek_file_missing`, `kek_file_unsafe`,
  `kek_file_malformed`, `kek_mismatch`, `wrapped_key_unreadable`.

## Preconditions

- Shell access to a host that can reach the fleet database, with the `control-plane` binary
  (the image's `flotestro-control-plane`, or the admin-tools container).
- A recent `pg_dump` of the fleet database. The migration is one transaction, but the
  procedure that follows it is not.
- A directory to write the backup of the state before each change to; every command requires
  `--backup-to` and refuses to overwrite a file it finds there. It must not be inside the
  state directory: `crypto forget-files` copies the key files there before removing them, and
  a copy that lives in the directory being emptied is not a copy.
- `flotestro-admin-tools backup` takes the database and the state directory. It does not take
  the key encryption key, and it is not meant to: the key is kept apart, by different people.

## The key itself

Exactly one format is accepted: 64 hexadecimal characters, which is 32 bytes, with at most
the single trailing newline the command that writes a secret leaves behind. Anything else —
the wrong length, a character outside hexadecimal, a second line, an empty file — is
refused rather than tidied up, because a key that was quietly repaired is a key nobody can
reproduce.

```fish
umask 077
openssl rand -hex 32 > flotestro-kek
```

The file is read with the link not followed and judged on the descriptor that was opened:
it must be a regular file, owned by root or by the panel's own account, and not readable or
writable by the group or by anybody else (`0400`). Whoever can rewrite this file decides
what the installation's records are sealed with.

Mount it at `/run/secrets/flotestro-kek`, or name another path with `-kek-file` /
`FLOTESTRO_KEK_FILE`. There is no flag and no environment variable that carries the key
itself, only the path.

In the Compose deployment the key goes in `./secrets/kek` and `init` copies it beside the
other secrets. `init` runs when the deployment is created and not again, so a key added to
an existing deployment needs it brought down and up:

```fish
podman-compose down
podman-compose up -d
```

The volumes survive that. Restarting the control plane alone does not bring the key in, and
podman will not recreate one container of a pod by itself.

The key belongs in a different backup from the database, kept by different people. A backup
that can be restored is the database dump **and** the key encryption key **and** the
installation identifier; any two of the three are not a backup.

## Moving the keys into the database

1. Look at what would move. The dry run prints what the run will print and changes nothing:

   ```fish
   flotestro-control-plane crypto import-state --dry-run --backup-to /var/backups/flotestro
   ```

   The report names every key, its purpose, where it was read from, and a digest of it. If a
   key you expect is missing from that list, stop: `import-state` moves what it finds, and a
   key left behind is an installation that will start, serve, and then fail to renew a
   certificate weeks later.

   The certificates of the authorities withdrawn from signing (`ca-retired/<serial>.pem`) are
   in the list too, under `retired-authority`. They carry no key, but the fleet recognises the
   hosts they issued for until the last of those has renewed, so they travel with everything
   else.

2. Move them:

   ```fish
   flotestro-control-plane crypto import-state --backup-to /var/backups/flotestro
   ```

   Every key is wrapped and read back before anything is written, and all of them are
   written with the installation record in a single transaction. One key that cannot be read
   back stops the whole migration; nothing is left half moved.

   The files are **not** removed. Until you say otherwise they are the way back.

3. Restart the panel with the key mounted. The `crypto` block of `GET /api/v1/status` should
   now say `db-sealed` and carry the `kek_id` the command printed.

4. Start the second replica against the same database with the same key mounted, and confirm
   it serves. That is the thing the whole stage was for.

## Rotating the key encryption key

The keys themselves do not change — the envelopes, the certificates and the pins the hosts
hold are untouched. Only the wrapping moves, which is why this can be done with the panel
running and why losing the old key afterwards costs nothing.

```fish
umask 077
openssl rand -hex 32 > /run/secrets/flotestro-kek-next
flotestro-control-plane crypto rewrap-kek --new-kek-file /run/secrets/flotestro-kek-next \
    --dry-run --backup-to /var/backups/flotestro
flotestro-control-plane crypto rewrap-kek --new-kek-file /run/secrets/flotestro-kek-next \
    --backup-to /var/backups/flotestro
```

Every row and the record move together, so there is no moment in which the database names
one key and holds rows wrapped with another. Then mount the new key as
`/run/secrets/flotestro-kek` on every replica and restart them. A replica still holding the
old key refuses to start with `kek_mismatch`; it does not serve half the installation.

The backup written before the rewrap holds the rows as they were. They open with the old
key and with no other, so keep that key until every replica is running on the new one.

## Going back

```fish
flotestro-control-plane crypto revert-state --dry-run --backup-to /var/backups/flotestro
flotestro-control-plane crypto revert-state --backup-to /var/backups/flotestro
```

The files are written first and the rows are dropped only once they are there, so an
interrupted revert leaves the keys in the database rather than nowhere. Restart the panel
afterwards; the `crypto` block says `local-sealed` again.

This works as long as the files exist or the rows do. It stops working once neither is true,
which is what the next section is about.

## Removing the files

`crypto forget-files` is the step that closes the way back. It never runs on its own, and it
asks six questions, refusing on the first "no":

1. the migration is finished, and with the key this deployment holds;
2. every key opens from the database and holds what the file holds — an extra file is as
   much of a refusal as a missing one;
3. the marker in the state directory names the installation the database describes;
4. the crypto state still stands at the revision you pass in `-expect-revision`;
5. you say the installation's own identifier back in `-confirm-installation`;
6. the warning about what stops working is printed before anything is removed.

```fish
flotestro-control-plane crypto forget-files --dry-run --backup-to /var/backups/flotestro
flotestro-control-plane crypto forget-files --backup-to /var/backups/flotestro \
    -expect-revision <revision> -confirm-installation <installation-id>
```

The revision and the identifier are in the `crypto` block of `GET /api/v1/status`.

The files are copied into the backup directory before they go. What the command then does is
**remove and unlink** the files and synchronise the directories. On an SSD, on a
copy-on-write filesystem or on network storage that is not a guaranteed erasure of the
bytes, and nothing here claims otherwise. If the material must be provably gone, that is a
property of the storage, not of this command.

After this, a panel from before the keys moved into the database will not start against this
installation without a backup of those files.

## Verification

- `GET /api/v1/status`, block `crypto`: `ok`, `provider: db-sealed`, the expected `kek_id`.
- Read a secret and renew one host's certificate: the first proves the secret store's keys
  opened, the second proves the fleet CA did.
- Stop the panel, move the state directory aside, start it again: it must come up and serve.
  That is the check that the installation really is in the database.

## Rollback

- Before `forget-files`: `crypto revert-state`, then restart.
- After `forget-files`: restore the files from the copy the command made, then
  `crypto revert-state`.
- A wrong key encryption key is not a rollback situation — the panel refuses to start with
  `kek_mismatch` and nothing is damaged. Mount the right key.

## Codes

`kek_file_missing`, `kek_file_unsafe`, `kek_file_malformed`, `kek_mismatch`,
`wrapped_key_unreadable`, `secrets_key_unavailable`.
