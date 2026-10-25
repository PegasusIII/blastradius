# TEST_REPORT: BlastRadius 0.2.0-exp (definitions v0.2.0)

Run: Mon 26 Oct 2026, ~07:40 AEST (Brisbane), re-run after the "fix first" changes, on the shared build box. Runtime: rootless **podman** 4.x (installed on the box for this run). The fixture images are `tests/containers/*.Containerfile`. Every test runs with **`--network none`**, and the checker runs as the **non-root user `bruser`**.
Inputs: a test definitions file with fake IDs (`TEST-RT-1`, `TEST-CA-1`, `TEST-INFO-1`, `TEST-PKG-1`), fake PHP branches 9.1/9.2, and a self-generated test PKI (distrusted root, intermediate and leaves, a good root, an unknown root), signed with a throwaway Ed25519 key. No acceptance test depends on real advisory data. Real data is exercised separately in the "real-world smoke" runs.

Reproduce: `tests/build_images.sh && tests/run_container_tests.sh`. Raw logs are in `tests/results/<distro>.txt` and `tests/results/<distro>-real.txt`.

## Summary
| Distro (image) | Pkg mgr | Acceptance tests | Distro pkg-rule tests | Perf (AT-1.4) | Real-world smoke with bundled defs v0.2.0 |
|---|---|---|---|---|---|
| Debian 12 | dpkg | **40/40 pass** | **4/4 pass** | 19s | PHP 8.2.35 cli/fpm/mod_php NOT AFFECTED via the Debian tracker row (8.2.35-1~deb12u1, DLA-4848-1). G3 absent. C1/C3 present -> NOTE only -> **OK** (exit 0). *Was ROTATE FIRST in v0.1.0* |
| Ubuntu 24.04 | dpkg | **40/40 pass** | **4/4 pass** | 15s | PHP 8.3.6 cli/fpm **NOT AFFECTED**: package 8.3.6-0ubuntu0.24.04.13 >= Ubuntu tracker fix. *False positive fixed.* python3-certifi still contains G3 -> **ROTATE FIRST** (exit 10). C1/C3 NOTE. Node UNKNOWN (not counted, since an AFFECTED result wins) |
| Rocky 9 (9.3) | rpm | **40/40 pass** | **4/4 pass** | 12s | PHP 8.0.30 **NOT AFFECTED**: php-cli/php-fpm 8.0.30-8.el9_8.1 >= RLSA-2026:87151. *False EOL flag fixed.* OS bundle still contains G3 -> **ROTATE FIRST** (exit 10). Java UNKNOWN (no keytool) |
| Alpine 3.20 | apk | **40/40 pass** | **4/4 pass** | 11s | php83 8.3.15-r0 **AFFECTED** (upstream comparison; the Alpine secdb has no v3.20 entry for these CVEs) -> **PATCH FIRST** (exit 20). emSign roots absent |

New tests this round:
- **AT-4.5** (all distros): a `ca_info` incident whose root is present in the OS bundle and certifi gives only `NOTE ... info only (does not change verdict)`, no ACTIONS, and never ROTATE or PATCH.
- **PK-1..PK-4** (`tests/pkg_rules.sh`, run in the `-real` images against the real installed PHP packages, with fake signed definitions):
  - PK-1: installed == distro fix -> NOT AFFECTED with the advisory cited, even though the upstream rule says affected.
  - PK-2: installed < distro fix -> AFFECTED and PATCH FIRST (checks native ordering with epochs: dpkg `99:0`, rpm `99:0-0`, apk `999.0-r0`).
  - PK-3: no tracker row for this release -> on Ubuntu/Rocky `UNKNOWN (needs verification ...)` and VERDICT UNKNOWN; on Debian/Alpine, fallback to the upstream comparison.
  - PK-4: an unpackaged copy of PHP (like a source build) -> upstream comparison.

Also: `shellcheck -s sh bin/blastradius tools/*.sh` is clean. `--json` output (including INFO rows) validates against `schema/report.schema.json` (python-jsonschema, on the build box).

## Acceptance tests covered (identical on every distro)
| AT | Check | Result |
|---|---|---|
| 1.1 | Clean host -> `VERDICT: OK`, exit 0, `find / -xdev -newer` before/after diff shows no changed files (Rocky: `UNKNOWN`/30 is expected, because Rocky ships a Java cacerts without keytool) | pass x4 |
| 1.2 | Completes with `--network none` | pass x4 |
| 1.3 | Unreadable certifi bundle -> `UNKNOWN (permission denied: path)`, run completes | pass x4 |
| 1.4 | 50 *distinct* certifi bundles (120-148 certs each) + 200 leaf files in < 30 s | pass x4 (12-20 s) |
| 2.1-2.5 | Below fixed -> AFFECTED with path/version/SAPI. At fixed -> NOT AFFECTED. cli and fpm listed separately. Uncovered branch -> UNKNOWN. `-1~deb12u1` suffix handled | pass x4 |
| 3.1 | Only the virtualenv with the test root is AFFECTED | pass x4 |
| 3.2 | Java cacerts + keytool -> AFFECTED (Debian, real JDK 17 keytool). cacerts without keytool -> `UNKNOWN (keytool not found)` (Ubuntu, Rocky, Alpine) | pass x4 |
| 3.3 | Node -> version + `embedded store: version-match only`, UNKNOWN without a rule | seen in Ubuntu/Alpine real smoke (not a scripted assertion) |
| 3.4 | Go/rustls advisory line | pass x4 |
| 4.1-4.5 | OS bundle containing the test root -> AFFECTED. Absent + pkg >= fixed -> NOT AFFECTED. Absent + pkg < fixed -> note `package older than fixed version`. Correct pkg manager/bundle path. `ca_info` root present -> NOTE only, verdict unchanged | pass x4 |
| 5.1-5.5 | nginx leaf under the distrusted intermediate -> AFFECTED with path, config, CN, notAfter. Unreferenced letsencrypt leaf -> NOT AFFECTED + unreferenced. Leaf-only by issuer name -> AFFECTED. Unknown issuer -> `UNKNOWN (chain incomplete)`. Apache/HAProxy/Postfix refs found. **strace**: `*.key` never opened, and a private key in a `.pem` file is only header-peeked | pass x4 |
| 6.1-6.5 | PATCH FIRST ordering (runtime then CA). ROTATE FIRST + reissue action. UNKNOWN verdict with reasons. Remediation for the host's package manager printed word for word. Byte-identical reruns | pass x4 |
| 7.1-7.3 | `--json` is a single valid document. Exit codes 0/10/20/30/2. Hostname only with `--include-hostname` | pass x4 |
| 8.1-8.4 | `--definitions` header shows version. One changed byte -> exit 2 `definitions signature invalid`. Invalid field -> exit 2 naming it (`FP.sha256`). Missing .sig / wrong key -> exit 2. Bundled defs used by default with signature OK | pass x4 |

**Not tested / not built (paid tier, post-gate):** US-9 to US-12 (`--report`, backend, alerts) and US-13. `--report` currently exits 2 with "not available in the experiment build". AT-7.3's host-id file is not implemented, because no `--report`.

## Bugs found and fixed during testing
1. mawk (Debian/Ubuntu) has no `{64}` regex intervals, so every definitions file was rejected. Now uses a `length()` check.
2. Perf: forking openssl for every cert in a bundle took 363 s on the perf fixture. The checker now lists subjects in one pipeline and only fingerprints certs whose CN matches a definitions label (the fingerprint is still the deciding match). Result: 12-20 s.
3. Alpine base images ship `ca-certificates-bundle`, not `ca-certificates`, so the version read as unknown. Both are handled now.
4. Test-harness issues (not checker bugs): Rocky has no `cmp`, and `su`'s PAM updates `/var/log/lastlog`. Both are excluded or worked around in the tests.

## Fixed this round (v0.2.0)
1. **Distro backports.** Added the `distro_package_fixed` rule (TSV `PKGFIX`) with 19 rows sourced from official trackers and cited per row in incidents.json. The Ubuntu 24.04 and Rocky 9 false positives are gone. A bug found during testing: `mod_php` is packaged as `libapache2-mod-php8.2`, which the binary-name prefix didn't match. Matching now also uses the source package (`${source:Package}` / `%{SOURCERPM}`).
2. **G3 verified.** CCADB (Mozilla "Removed CA Certificate Report") lists `emSign ECC Root CA - G3` with SHA-256 `86A1ECBA...36BBE6B`, matching ours, under removal bug 2084101. That bug blocks incident bug 2083449. Added the 6 compromised TLS intermediates' fingerprints from bug 2083449 (served-chain detection) and their issuer names.
3. **C1/C3 are info-only** (`kind: ca_info`). Debian 12 went from ROTATE FIRST to OK.
4. **Release key generated** outside the repo (encrypted). Rotation is documented in `RELEASING.md`. It is not embedded and not published.

## Open issues (to fix before a public release)
1. **Tracker gaps (shown as UNKNOWN/needs-verification, never guessed):**
   - RHEL php:8.2/8.3 (EL9) and php:8.2/7.4 (EL8) module NEVRAs. The RHSAs exist, but only the Rocky NEVRAs were copied, so RHEL module hosts get UNKNOWN.
   - RHEL 9 php:8.4 is still "Affected" with no fix.
   - AlmaLinux, CentOS Stream and Oracle Linux not sourced.
   - Ubuntu 18.04 and older (ESM only).
   - Alpine 3.20 and older have no secdb entry. Alpine uses the upstream comparison, so php83 8.3.15 is AFFECTED; I believe that's correct, but it isn't tracker-confirmed.
   - Remi/SCL PHP (`/opt/remi`): not owned by a distro package row, so it falls back to the upstream version (on RHEL-family, Remi packages are rpm-owned and get UNKNOWN).
2. **G3 issuance path.** Bug 2083449 gives the intermediates' issuer as `emSign Root TLS CA - G3`, a name that isn't in Mozilla's included or removed reports. Mozilla links its G3 removal to the incident, but how the intermediates chain to `emSign ECC Root CA - G3` (presumably a cross-sign) is not verified. The Sectigo cross-signed copies of the intermediates aren't listed. CCADB says G3 was removed in NSS 3.132, while Mozilla's blog and Arch say 3.131.1; there's no version rule, so this doesn't affect detection.
3. **Fixed `ca-certificates` versions per distro are not sourced** (only Arch), so CA detection is by fingerprint only.
4. The definitions are still signed with the **dev key**. The release key swap and multi-key rotation support are documented as release steps, not implemented.
5. Leaf chain matching uses issuer CN, not AKI. Java keystores are listed with the public default password `changeit` only.
6. Definitions are consumed as a compiled, signed TSV; the JSON is the source of truth.
7. No `--report` / backend / host-id (paid tier, gated on the experiment).
