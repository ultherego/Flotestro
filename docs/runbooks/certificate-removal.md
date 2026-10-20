# Taking a deployed certificate off a host

The panel deploys a certificate and its key to a host (`certificate.deploy`) and
removes an anchor from a host's trust store (`certificate.trust.remove`). It has
**no operation that takes a deployed certificate and its key off a host**, and this
runbook is the manual procedure for it. Where a step is the operator's, on the host,
it says so; nothing here is a route the product does not have.

Use it when a service is retired, a name is no longer served, or a key is thought to be
exposed. It leaves the panel's record of what was deployed in place on purpose: that
record is the evidence of what stood on the host, and it is kept.

## 1. Find what the panel put there

```fish
GET /api/v1/hosts/<host-id>/certificates/deployments?path=<certificate-path>
```

The newest entry names the `path`, the fingerprint, the `key_secret` the key was
fetched from, the job that deployed it (`job_id`) and who ordered it. The key's path
and the unit that was reloaded are those of the **deploy order**: read them from the
job (`GET /api/v1/jobs/<job_id>`), not from memory.

## 2. Stop the service using it

On the host, as root, take the reference out of the service's own configuration, so
that the next reload does not look for the files. The product cannot do this for you:
what a service names is its own file.

## 3. Remove the files

```fish
sudo systemctl reload <unit>        # the unit of the order, after the reference is gone
sudo rm -- <certificate-path> <key-path>
```

Reload **before** removing the files if the service would otherwise fail on a missing
file at reload, and after if it would keep serving the old certificate from memory;
check which with `systemctl status <unit>`. If the key is thought exposed, replace it
at the issuer as well: removing a file does not make a copy of it harmless.

## 4. Stop the panel watching the path

```fish
DELETE /api/v1/hosts/<host-id>/certificates/targets?path=<certificate-path>&reason=<why>
```

A path the panel still watches keeps being scanned, so the inventory goes on carrying a
certificate that is no longer on the host. The reason is kept in the audit trail.

## 5. Verify

```fish
GET /api/v1/hosts/<host-id>/certificates
```

The path is no longer listed, and the unit answers (`systemctl is-active <unit>`).
The panel's deployment history still shows the deployment; that is expected.

## What stays behind

The key's **secret** in the panel's store (`key_secret`) is not removed by any of
this. Retire it through the secrets screen when nothing else names it.

## Going back

Deploy the certificate again with `certificate.deploy` (plan, consent, deploy). The
key is fetched from the store, so a key removed from the store cannot be put back.
