# attest-pki-website

The two sites of the Encedo attestation host, the CLI verifier and the scripts that deploy them.
One folder per site: pki.encedo.com is static, attest.encedo.com is a PHP service in Docker.

| folder | site | contents |
|---|---|---|
| [`pki.encedo.com/`](pki.encedo.com/) | https://pki.encedo.com/ | Certificate authorities that attest Encedo HEM devices: certificates, revocation lists, `SHA256SUMS` and the page that explains them |
| [`attest.encedo.com/`](attest.encedo.com/) | https://attest.encedo.com/ | Stateless validation of HEM attestation tokens (PHP 8.4, Docker); not static, see its [README](attest.encedo.com/README.md) |
| [`attest_verify/`](attest_verify/) | - | CLI verifier (PHP + openssl CLI): prepare an attestation request, verify the token incl. ECDH / KEM proof of possession |
| [`ct-watch/`](ct-watch/) | - | Watch of the public TLS certificates of our domains in the Certificate Transparency logs |

## pki.encedo.com

```
Encedo Root CA                 RSA 4096,    valid until 2040-12-31
└─ Encedo Attestation CA       ECDSA P-256, valid until 2030-08-21
   ├─ Encedo Custody CA        ECDSA P-256, valid until 2030-08-21   -> HEM PPA device certificates
   └─ Encedo EPA Custody CA    ECDSA P-256, valid until 2030-08-21   -> HEM EPA device certificates
```

The issuer of a device certificate tells the model: Custody CA for a HEM PPA, EPA Custody CA for a HEM EPA.
EPA device certificates carry AIA and CRL distribution points (`epa-custody-ca.cer`, `epa-custody-ca.crl`).

| file | what |
|---|---|
| `*-ca.cer` | CA certificate, DER (the form named in the certificates' AIA fields) |
| `*-ca.pem` | the same certificate, PEM |
| `intermediates-chain.pem` | Custody CA + Attestation CA (HEM PPA), in the order a client sends them |
| `epa-intermediates-chain.pem` | EPA Custody CA + Attestation CA (HEM EPA), in the order a client sends them |
| `*-ca.crl` | revocation list of each CA, DER (the form named in the CRL distribution points) |
| `SHA256SUMS` | SHA-256 of every file above |
| `index.html` | the page; no scripts, no external resources |

Only public material lives in this folder: no private key and no CA database.

### Verify a device

```sh
cd pki.encedo.com
sha256sum -c SHA256SUMS
openssl x509 -in root-ca.pem -noout -fingerprint -sha256
#   B2:8F:4E:E4:CF:26:02:82:60:CF:4F:0D:B1:8B:D2:FB:72:34:D1:72:92:57:97:DC:A7:F8:1E:53:A2:81:6E:9C
openssl verify -CAfile root-ca.pem -untrusted intermediates-chain.pem device.pem        # HEM PPA
openssl verify -CAfile root-ca.pem -untrusted epa-intermediates-chain.pem device.pem    # HEM EPA
```

With revocation:

```sh
cat root-ca.pem intermediates-chain.pem epa-custody-ca.pem > chain.pem
for c in root attestation custody epa-custody; do openssl crl -inform DER -in $c-ca.crl; done > crls.pem
openssl verify -crl_check_all -CAfile chain.pem -CRLfile crls.pem device.pem
```

### Serving

`deploy/deploy.sh pki` copies the folder to the web root (see [Deploy](#deploy)). Whatever serves it must:

- send `application/pkix-cert` for `.cer` and `application/pkix-crl` for `.crl`;
- serve `.cer` and `.crl` over plain HTTP as well as HTTPS, without a redirect, because some clients fetch AIA and CDP URLs only over HTTP.
- send `Access-Control-Allow-Origin: *` on `.cer`, `.crl`, `.pem` and `SHA256SUMS`, so a browser page (hem-sdk-js) can fetch the chain and the revocation lists; they are public, nothing is behind a cookie.

### Revocation lists expire

The CRLs are valid until **2027-11-04** (the EPA Custody CA's until 2027-11-06; renew all four together). Regenerate them before that date, update the dates on the page,
rebuild `SHA256SUMS`, commit, and deploy all of them together:

```sh
sha256sum *.cer *.crl *.pem > SHA256SUMS
# on the host, after the push:
cd /opt/attest-pki-website && git pull && deploy/deploy.sh pki && deploy/deploy.sh refresh
```

`refresh` makes attest.encedo.com pick the new CRLs up at once instead of at the next daily run.

## Deploy

Both sites run on one host: nginx on the host serves pki.encedo.com from disk and terminates TLS for
attest.encedo.com, which runs in Docker on `127.0.0.1:8080`. Everything comes from this repository,
checked out at `/opt/attest-pki-website`:

```sh
cd /opt/attest-pki-website && git pull && deploy/deploy.sh          # all
deploy/deploy.sh pki        # only the static PKI site
deploy/deploy.sh attest     # rebuild the image, refresh the data, replace the container
deploy/deploy.sh nginx      # install deploy/nginx/*, test, reload
```

| file | installed as |
|---|---|
| `deploy/nginx/pki.encedo.com.conf` | `/etc/nginx/sites-available/pki.encedo.com` |
| `deploy/nginx/attest.encedo.com.conf` | `/etc/nginx/sites-available/attest.encedo.com` (proxy to the container; request body up to 32 KB, the service itself takes 24 KB; SKID lookups not logged) |
| `deploy/nginx/attest-limits.conf` | `/etc/nginx/conf.d/attest-limits.conf` (per-IP limits: POST 1/s burst 10, all requests 10/s burst 40, 10 connections; over the limit: 429) |
| `deploy/nginx/attest-proxy.conf`, `pki-types.conf` | `/etc/nginx/snippets/` |
| `deploy/attest-refresh.cron` | `/etc/cron.d/attest-refresh` (daily PKI sync + index rebuild) |

The service data lives in `/srv/attest`, outside the repository and mounted read-only into the container:
`issued/*.pem` are the device certificates issued by the Encedo Custody CA, `revoked.txt` the revoked SKIDs.
The device certificates are never listed or served; the service only answers whether a given SKID is known.

`issued/` is not filled automatically. The certificates are the `NN.pem` files the Custody CA writes next to its
database (`ca/custody-ca/` on the signing host); copy the new ones into `/srv/attest/issued/` and run
`deploy/deploy.sh refresh` to rebuild the index. A revoked device goes into `revoked.txt` (SKID, SHA-1 or SHA-256 hex,
one per line) followed by the same `refresh`.

TLS certificates come from Let's Encrypt (certbot, webroot `/var/www/acme`), renewed by `certbot.timer`.

## ct-watch

Every hour `ct-watch/ct_watch.py` asks the Cert Spotter API (`api.certspotter.com/v1/issuances`, no key, 10 queries
an hour) for the certificates logged in public CT since its last run, for each domain in
[`ct-watch/domains.txt`](ct-watch/domains.txt) with all its subdomains. It is the cheap way to read CT for a few
domains: a local monitor would have to download every entry of every log.
The limit is a bucket of about 10 queries refilled at about 10 an hour, one query per domain and run (more only when a
domain has more new certificates than one page), so an hourly run fits about 8 domains. After a 429 the run stops
asking, and no run - manual ones included - asks again before the `Retry-After` has passed; the domain checked longest
ago goes first, so the same domains do not lose out every time.

The first run of a domain records what is there and reports nothing. After that **every** new certificate is
reported, labelled `renewal` (known names, known issuer), `NEW NAME` or `NEW ISSUER` (an issuing organisation never
seen on that domain - the one to look at first). One run, one alert, with a `crt.sh` link per certificate:

- **Uptime Kuma** (status.encedo.com), a Push monitor: `down` with a short text when something is new, `up` on a clean
  run, nothing when the API failed - so the monitor's 2 h heartbeat also catches a dead watch. The push URL is a
  secret, in `/etc/ct-watch/kuma.url` (mode 600), not in git.
- **`/etc/ct-watch/notify`**, an executable getting the full text on stdin; on attest it hands it to the onchato bot.

An alert that does not get through (Kuma unreachable, the hook failing) is kept in the state and sent again every run,
even during a rate-limit wait, until it does; meanwhile Kuma gets no `up`. A new certificate joins a pending Kuma alert.

State: `/var/lib/ct-watch/state.json` (last id, names and issuers per domain, the latest reports).
`python3 ct-watch/ct_watch.py status` shows the last run and the latest certificates. A domain added to the list gets
its own silent baseline. Tests: `python3 ct-watch/test_ct_watch.py` (no network).

```sh
deploy/deploy.sh ctwatch    # run the tests, install /etc/cron.d/ct-watch (hourly, minute 23, log /var/log/ct-watch.log)
```

## License

[MIT](LICENSE)
