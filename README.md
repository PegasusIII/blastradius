# BlastRadius (experiment build)

> **Want fleet-wide checks and alerts?** Join the BlastRadius Pro waitlist ($9): https://tally.so/r/OQQDr7

**Is this host exposed to this week's incident, and what do I fix first?**

BlastRadius is a small, read-only POSIX shell script. Run it on a Linux host as a normal user. It checks:

- **PHP builds:** every PHP binary (CLI, FPM, CGI) and `mod_php`, with version and SAPI, compared against the fixed versions for tracked runtime CVEs.
- **System trust store:** the `ca-certificates` version and whether distrusted roots (by SHA-256 fingerprint) are still in the OS bundle.
- **Language trust stores:** Python `certifi` bundles, Java `cacerts` (needs `keytool`), and the Node version (Node embeds its roots, so it can only be matched by version). Go and rustls apps compile their roots in; you get a note about them, but they aren't scanned.
- **Deployed certificates:** leaf certs referenced by nginx, Apache, HAProxy and Postfix configs, plus `/etc/letsencrypt/live`, `/etc/ssl` and `/etc/pki/tls/certs`. Any cert that chains to a distrusted CA gets flagged. Private keys are never parsed.

It then prints **one verdict per host** (`PATCH FIRST` / `ROTATE FIRST` / `OK` / `UNKNOWN`) and an ordered action list with copy-paste commands for your package manager.

```
$ sh blastradius
VERDICT: PATCH FIRST
php:     AFFECTED BR-2026-0001  /usr/bin/php8.3  [version=8.3.6 sapi=cli fixed=8.3.36]
os_ca:   AFFECTED BR-2026-0002  /etc/pki/tls/certs/ca-bundle.crt  [contains: emSign ECC Root CA - G3]
ACTIONS (in order; BlastRadius never runs these for you):
1. [BR-2026-0001] PHP2Shell: unauthenticated RCE in PHP (CVE-2026-109618, CVE-2026-109619)
     sudo apt-get update
     ...
```

## Safety guarantees
- **Read-only.** It never writes, moves or deletes files outside its own `$TMPDIR` scratch dir (which it removes when done). It never installs packages, never restarts services, and never calls `sudo`. Fix commands are printed, never run.
- **No network** unless you pass `--definitions https://...`.
- **No root needed.** Root only widens what it can read. Files it can't read are reported as `UNKNOWN (permission denied: <path>)`.
- **Signed definitions.** Incident data is a signed (Ed25519) data file. It holds only thresholds, fingerprints and text, never code the checker would run.

## Usage
```
blastradius [--json] [--definitions PATH|URL] [--scan-roots "/usr /opt /srv /home /var/www"] [--include-hostname] [--no-color]
```
Exit codes: `0` OK, `10` ROTATE FIRST, `20` PATCH FIRST, `30` UNKNOWN, `2` usage/definitions error. Run it across a fleet with ssh/Ansible and use `--json` to aggregate (schema: `schema/report.schema.json`).

Requirements: POSIX `sh`, coreutils/busybox, and `openssl` (optional; without it the cert checks report `UNKNOWN`, and only the bundled definitions are accepted, flagged as unverified). `keytool` is optional and only used for Java.

## Tracked incidents (definitions v0.2.0)
| ID | What | Data status |
|---|---|---|
| BR-2026-0001 | PHP CVE-2026-109618 / -109619 ("PHP2Shell"). Upstream fixes: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; <= 8.1 is EOL upstream. Distro fixes (backports) for Ubuntu 20.04/22.04/24.04/26.04, Debian 12/13, RHEL 9/10, Rocky 8/9/10 and Alpine 3.21/3.22 | Verified against php.net, GHSA-6wmf-4rv5-p3rp and CERT-EU 2026-018; distro rows from the Ubuntu, Debian, Red Hat and Rocky trackers and the Alpine secdb (checked 2026-10-26) |
| BR-2026-0002 | emSign ECC Root CA - G3 removed from Mozilla NSS (compromised eMudhra intermediates); also the 6 compromised TLS intermediates (in served chains) | Root fingerprint verified against CCADB's Mozilla removed-certificates report; Mozilla bug 2084101 (G3 removal) blocks incident bug 2083449. The exact cross-sign path from the intermediates to G3 is not verified |
| BR-2026-0003 | emSign Root CA - C1 / ECC Root CA - C3 planned removal. **Info only**: shown as `NOTE`, never changes the verdict or exit code | Fingerprints from Mozilla bug 2083709 and CCADB |

**Distro backports.** For a PHP binary or `mod_php` installed from a distro package, BlastRadius looks up the owning package (read-only `dpkg-query -S` / `rpm -qf` / `apk info --who-owns`). It then compares the package version with the distro tracker's fixed version, using the distro's own version ordering, and cites the advisory. On a backport distro (Ubuntu, RHEL, Rocky, Alma, CentOS, Oracle) with no tracker row in the definitions, the result is `UNKNOWN (needs verification ...)`; it never guesses from the upstream number. PHP you built yourself, Debian, and Alpine without a row fall back to the upstream comparison.

Sources are listed in `definitions/incidents.json`.

## What it is not
It is not a cert inventory or expiry monitor, a vulnerability scanner for app dependencies (use composer audit / npm audit / pip-audit), a port scanner, or an exploit or forensics tool.

## Monitoring (coming, waitlist)
An optional, paid tier (**$9/mo**) will let hosts opt in to reporting, so you get an email/Slack alert when a *new* incident matches a host or cert you've already reported. Nothing is ever sent unless you pass `--report`, which this build doesn't include yet.

## Development
- `tools/compile_defs.sh definitions/incidents.json definitions/incidents.tsv` (needs jq), then `tools/sign_defs.sh KEY definitions/incidents.tsv`. Release keys and rotation: see `RELEASING.md`
- `tests/build_images.sh && tests/run_container_tests.sh` (podman or docker; fixtures for Debian 12, Ubuntu 24.04, Rocky 9, Alpine 3.20; tests run with `--network none`; `tests/pkg_rules.sh` covers distro package rules against the real PHP packages)

License: MIT.
