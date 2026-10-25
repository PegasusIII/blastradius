# Releasing and signing keys

BlastRadius trusts exactly one Ed25519 public key, embedded in `bin/blastradius` as `BR_PUBKEY`.
Definitions (`definitions/incidents.tsv`) are rejected unless `incidents.tsv.sig` verifies against it.

## Keys
| Key | Where | Use |
|---|---|---|
| dev key | `<offline-keys-dir>/dev-signing.key` (outside the repo, dir 0700) | Signs the definitions in this local build. It is the key currently embedded. **Never ship it.** |
| release key `release-2026-01` | `<offline-keys-dir>/release-2026-01.key` (Ed25519, AES-256 encrypted PEM, 0600). The passphrase is in `release-2026-01.pass` (0600) | Will sign published definitions. **Not embedded yet, not published.** Public key SHA-256 (DER SPKI): `c25697b87117112dce2a1451b8635292743a0a16f9878151684d4054b0ca9a4b` |

Before any public release: move `release-2026-01.key` and its passphrase off this shared build box. Keep them in separate places, e.g. the key on an offline USB plus a second encrypted backup, and the passphrase in a password manager. Then delete the box copies. Private keys never go in git (`.gitignore` covers `*.key`).

## Release steps (only after the maintainer approves)
1. Replace `BR_PUBKEY` in `bin/blastradius` and `definitions/signing-pubkey.pem` with `release-2026-01.pub.pem`.
2. `tools/compile_defs.sh definitions/incidents.json definitions/incidents.tsv`
3. Sign on the machine that holds the key:
   `openssl pkeyutl -sign -rawin -inkey release-2026-01.key -passin file:release-2026-01.pass -in definitions/incidents.tsv -out definitions/incidents.tsv.sig`
4. Verify: `openssl pkeyutl -verify -pubin -inkey definitions/signing-pubkey.pem -rawin -in definitions/incidents.tsv -sigfile definitions/incidents.tsv.sig`
5. Run the full container suite. Publish the public key fingerprint in the README and release notes.

## Rotation
- **Planned (yearly, or when a maintainer changes):** generate `release-YYYY-NN`. Ship a checker release that embeds the old and new keys and accepts either (`BR_PUBKEY` becomes a list). Sign definitions with the new key from then on. Drop the old key one release later. Bump the checker minor version and note it in the changelog.
- **Compromise:** stop publishing definitions signed with the old key immediately. Ship a checker release that embeds only the new key. Post an advisory with the old key's fingerprint and tell users to upgrade the checker. Old checkers will keep trusting the old key; a single embedded key can't be revoked remotely. That limit is documented and accepted for the free CLI.
- Every key's fingerprint, creation date and retirement date is listed in this file.

Status: the multi-key acceptance in the checker is **planned, not implemented** (it isn't needed until the first rotation).
