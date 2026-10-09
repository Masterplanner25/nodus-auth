# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No — upgrade; see the JWT backend note below |

## Known constraints

- `bcrypt` is pinned `<5.0` due to a `passlib` 1.7.4 incompatibility.
  This is a known limitation, not a vulnerability.

- **The `PyJWT` floor is security-relevant. Do not lower it.**

  `PyJWT>=2.15.1` is not a compatibility floor, it is the exclusion list for
  fixed advisories: `>=2.14.0` for CVE-2026-102271 (a DER-encoded public key
  accepted as an HMAC secret, bypassing PyJWT's own CVE-2022-29217 guard), and
  `>=2.15.0` for CVE-2026-102275 and CVE-2026-101918. It needs to keep moving
  rather than being set once.

  `tests/test_pyjwt_backend.py` asserts the *behaviours* the floor buys rather
  than the version string, so a downgrade fails the suite instead of passing a
  version check.

  **0.1.x shipped on `python-jose`, which carries CVE-2026-85394 /
  GHSA-3qf3-8w2g-rqmx (CRITICAL) with `last_affected: 3.5.0` and no fixed
  release.** Its newest release is also its last. Upgrade to 0.2.0.

- **An HMAC algorithm refuses asymmetric key material, and that guard is not
  redundant with PyJWT's.**

  Hand an HMAC algorithm a *public* key and it becomes the shared secret, so
  anyone holding that key — everyone — can mint a token for any subject.
  `nodus-auth` refuses it with `InsecureKeyError` at both the signing and the
  verifying call site.

  PyJWT 2.14.0+ refuses it too, but only when the key is `bytes`.
  `AuthSettings.SECRET_KEY` is a `str`, and the one lossless way DER reaches a
  `str` is latin-1 — so what PyJWT finally HMACs with is `key.encode("utf-8")`,
  which no longer parses as DER and passes its check. Measured on 2.15.1: the
  DER bytes are refused, and the latin-1 `str` carrying the same public key is
  **accepted**. An attacker derives those bytes from the public key as
  deterministically as the server does. Since a `str` is the only way DER enters
  this package's configuration, the upstream fix alone would leave the reachable
  path open. Not yet reported upstream; the guard here does not depend on the
  outcome either way.

  **What this means for you.** The default configuration — `HS256` with a shared
  secret from `generate_key()` — was never exposed, and every decode passes an
  explicit single-algorithm allowlist, so algorithm substitution and `alg: none`
  are rejected. If you configure an HMAC algorithm, the key must be a secret; if
  you want a keypair, use an asymmetric algorithm such as `RS256`. Supplying a
  keypair under `HS*` is an error rather than a silent forgery.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately to: **shawnknight@the-master-plan.com**

Include a description, steps to reproduce, and potential impact.
You will receive a response within 72 hours.
