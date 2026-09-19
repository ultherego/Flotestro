# Support bundle

## Purpose

Take everything a support engineer asks for first off one host - the diagnosis, the status,
the effective configuration, the journals of the agent and the helper, the state of the
units, the distribution, and the metadata of the host certificate - into one archive the
operator can read before sending it anywhere.

Nothing leaves the host by itself. The bundle is made only by an explicit command, it is
written to a file the operator names, and the path is printed. What the bundle may carry is
decided where the fields are known: every collector declares each of its fields as public,
sensitive or secret. The public and the sensitive travel, the secret is never collected, and
the manifest says what was left out and why.

## Signals

- A host that does not connect, a helper that does not answer, a renewal that keeps failing -
  anything where `flotestro-agentctl diagnose` alone does not settle the question.
- A support request that asks for "the logs": send the bundle instead of loose files, because
  the bundle is the form that was scanned.

## Preconditions

- The command runs on the host, as the operator of that host (`sudo`), not through the panel:
  there is no route that pulls a bundle off a host, deliberately.
- The target directory is the operator's own. The default is `$TMPDIR`, and the file is
  created with `O_EXCL` and mode `0600`: an existing name is a refusal, never an overwrite.

## Procedure

### Make a bundle

```
sudo flotestro-agentctl support-bundle
sudo flotestro-agentctl support-bundle --output /root/web-01-bundle.tar.gz
```

The name carries the host and the moment (`flotestro-support-<host>-<YYYYMMDD>T<HHMMSS>Z.tar.gz`),
so bundles of several hosts do not overwrite each other on the desk of the person reading them.

The summary says where the bundle went, how many files it holds, how many values were redacted,
how many fields were left out as secret, and that the scanner found nothing.

### Verify a bundle before sending it

```
flotestro-agentctl support-bundle --verify /root/web-01-bundle.tar.gz
```

The same scanner that gates the generation is run over an archive that already exists. It prints
the file count, the redaction policy the bundle was made under, and either `Findings:     none`
or one line per finding naming the file and the kind of thing found - never the thing itself.
Exit code 0 means the archive is clean to send, 1 means it is not.

A bundle made by an older agent may say `Policy:       not stated`. Verify it, and if it is
clean, say in the support request which agent version made it.

### When the generation is refused

The generation fails, nothing is left on the disk, and the refusal names the file and a code:

| Code | What was found |
| --- | --- |
| `bundle_private_key_found` | a private key block (`-----BEGIN … PRIVATE KEY-----`) |
| `bundle_bearer_token_found` | a bearer token in a header or a command line |
| `bundle_password_in_url_found` | a password written into a URL (`scheme://user:password@host`) |
| `bundle_enrollment_token_found` | an enrollment token (`flt_…`) |

These are the kinds no key names, so the redaction - which hides the values of keys called
token, password or secret - cannot catch them. A bundle carrying one of them is refused rather
than patched: a bundle that leaks is worse than no bundle.

What to do:

1. Read the named file on the host itself (`journalctl -u flotestro-agent.service`,
   `/etc/flotestro/agent.env`), find the line, and take the secret off the host: rotate it,
   remove the lingering enrollment token, stop the tool that pastes a key into its output.
2. Vacuum the journal if the secret is in it and rotation is not enough
   (`journalctl --rotate && journalctl --vacuum-time=1s`), knowing that this destroys history.
3. Make the bundle again and verify it.

## Verification

- `flotestro-agentctl support-bundle --verify <file>` prints `Findings:     none`.
- `tar tzf <file>` lists `manifest.json` first by name; `manifest.json` carries
  `redaction_policy`, the fields of every file with their sensitivity, and `omitted`.
- The file is `0600` and owned by whoever ran the command, and `<file>.sha256` beside it
  holds the archive's own digest in `sha256sum -c` form. `--verify` checks the two against
  each other.
- A file listed under `Withheld:` did not parse as the shape it was collected as, so its
  content was left out rather than sent unparsed - what cannot be walked cannot be shown to
  be free of the fields declared secret. `manifest.json` gives the code and the reason. Repair
  the file on the host and make the bundle again.

## Rollback

There is nothing to undo on the host: the bundle only reads. Delete the archive when the
support request is closed - it holds the journal of a service and the addresses of the fleet.

## Codes

`bundle_private_key_found`, `bundle_bearer_token_found`, `bundle_password_in_url_found`,
`bundle_enrollment_token_found` refuse the bundle outright. `bundle_file_unparsable` withholds
one file. `bundle_field_not_collected`, `bundle_field_redacted` and `bundle_field_pattern_only`
say in the manifest which layer kept a field out: never read at all, dropped because it was
declared, or hidden only by the pattern. All of them are in the panel's error guide
(`GET /api/v1/errors`) as well, because the panel now makes bundles of its own.
