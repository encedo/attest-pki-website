# attest.encedo.com

Stateless validation of Encedo HEM attestation tokens (`POST /api/system/config/attestation`). Design: Jira DEV-498.

| Method / path | Answer |
|---|---|
| `GET /` | Form: paste a JWT (or the whole `{"attestation": "..."}` reply) and optionally the device certificate, Validate |
| `POST /` | Status + tables of the JWT content (+ the device certificate) |
| `POST /v1/validate` | `{"jwt": "...", "crt": "..."}` (`crt` optional) → `{"status": "valid" \| "valid_unverified" \| "invalid", "expired": bool}` |
| `GET /v1/skid/<hex>` | `{"known": bool}` - SHA-1 (40 hex) or SHA-256 (64 hex) of `04‖x‖y` of the device key |
| `GET /v1/pki` | `{"certificates": [{subject, issuer, not_after, sha256, pem}]}` - Encedo CA certificates |

Device certificate (`crt` of `GET /api/system/config/attestation`: base64 DER, PEM, or the whole reply): when it is sent, it alone decides the device part.
It must chain device → Encedo Custody CA → Encedo Attestation CA → Encedo Root CA (pinned: SHA-256 of the DER `b28f4ee4…6e9c`), pass the CRLs of all three CAs,
and its key must be the `jwk` of the token; otherwise the status is `invalid`. The certificate date does not limit validity (a HEM cannot renew its certificate;
`openssl verify -no_check_time`). Without `crt` the SKID index below is used.

Status:
- `valid`: the JWT is intact (ES256 by its `jwk`, header `kid` = hash of `jwk`, claims, signature PoP if present) and the device key belongs to a not revoked Encedo device certificate (the `crt` sent, or the index).
- `valid_unverified`: the JWT is intact, the device key is not known.
- `expired: true` next to either: past `exp` (the token says so itself).
- `invalid`: anything else, including a revoked device. No reason is given.

A `pop.mac` (ECDH / KEM PoP) needs the verifier's ephemeral secret and is not checked here; [`attest_verify`](../attest_verify/) does it on the verifier side.

Nothing is stored and no JWT is logged. Body limit 16 KB. CORS only on `/v1/skid` and `/v1/pki`.

## Data (read-only)

```
pki/*.pem        Encedo CA certificates, published by /v1/pki (root-ca, attestation-ca, custody-ca from tools/sync_pki.php)
crl/*.crl.pem    CRLs of the three CAs (tools/sync_pki.php)
issued/*.pem     issued device certificates (input of the index)
revoked.txt      revoked device SKIDs, one hex per line
data/index.sqlite  built by tools/build_index.php, the only thing the service reads for lookups
```

`php tools/sync_pki.php [https://pki.encedo.com]` fetches the CA certificates and CRLs into `ATTEST_DATA` (default: the project root): every file is checked
against `SHA256SUMS`, the root against the pinned fingerprint, the chain and CRLs with `openssl verify`, and only then replaced. Run it daily from cron.

`php -d extension=pdo_sqlite tools/build_index.php [issued_dir] [revoked.txt] [out.sqlite]` rebuilds the index (written to a temp file, then renamed).
The SKID is computed from the certificate public key, not taken from the subjectKeyIdentifier extension.

## Run locally (Windows, PHP 8.4)

```
php tools/make_test_pki.php [--jwt <token file>]          # TEST ONLY: throw-away CA + device certificates (+ one for the jwk of a real token)
php -d extension=pdo_sqlite tools/build_index.php
php -d extension=pdo_sqlite -S localhost:8080 public/index.php
php tools/sync_pki.php
php -d extension=pdo_sqlite tests/run.php [real-token-file [real-crt-file]]
```

`pdo_sqlite` is shipped with PHP but not enabled in the default `php.ini`; `-d extension=pdo_sqlite` loads it for one run.
Ed448 / ML-DSA PoP checks use the openssl CLI ≥ 3.5 (`ENCEDO_OPENSSL`, default: Git for Windows ucrt64, then `openssl` in PATH).

## Docker

```
docker build -t attest-service .
docker run -p 8080:8080 -v /srv/attest:/data:ro attest-service      # /srv/attest/pki/*.pem, /srv/attest/data/index.sqlite
```

## Offline validation in an SDK

1. Read `crt` from the device (`GET /api/system/config/attestation`) and `/v1/pki` (cache it).
2. Check the JWT signature with `jwk`, that `jwk` is the public key of `crt`, and the chain `crt` → intermediate → root.
3. Optionally `GET /v1/skid/<hex>` (known, not revoked). Only the SKID leaves the client.
