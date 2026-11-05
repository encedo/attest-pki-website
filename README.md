# attest-pki-website

Static websites of the Encedo attestation host. One folder per site, served as is.

| folder | site | contents |
|---|---|---|
| [`pki.encedo.com/`](pki.encedo.com/) | https://pki.encedo.com/ | Certificate authorities that attest Encedo HEM devices: certificates, revocation lists, `SHA256SUMS` and the page that explains them |

## pki.encedo.com

```
Encedo Root CA             RSA 4096,    valid until 2040-12-31
└─ Encedo Attestation CA   ECDSA P-256, valid until 2030-08-21
   └─ Encedo Custody CA    ECDSA P-256, valid until 2030-08-21
      └─ HEM device certificates
```

| file | what |
|---|---|
| `*-ca.cer` | CA certificate, DER (the form named in the certificates' AIA fields) |
| `*-ca.pem` | the same certificate, PEM |
| `intermediates-chain.pem` | Custody CA + Attestation CA, in the order a client sends them |
| `*-ca.crl` | revocation list of each CA, DER (the form named in the CRL distribution points) |
| `SHA256SUMS` | SHA-256 of every file above |
| `index.html` | the page; no scripts, no external resources |

Only public material lives here. No private key, no CA database and no server configuration.

### Verify a device

```sh
cd pki.encedo.com
sha256sum -c SHA256SUMS
openssl x509 -in root-ca.pem -noout -fingerprint -sha256
#   B2:8F:4E:E4:CF:26:02:82:60:CF:4F:0D:B1:8B:D2:FB:72:34:D1:72:92:57:97:DC:A7:F8:1E:53:A2:81:6E:9C
openssl verify -CAfile root-ca.pem -untrusted intermediates-chain.pem device.pem
```

With revocation:

```sh
cat root-ca.pem intermediates-chain.pem > chain.pem
for c in root attestation custody; do openssl crl -inform DER -in $c-ca.crl; done > crls.pem
openssl verify -crl_check_all -CAfile chain.pem -CRLfile crls.pem device.pem
```

### Serving

Copy the folder to the web root of the site. The server must:

- send `application/pkix-cert` for `.cer` and `application/pkix-crl` for `.crl`;
- serve `.cer` and `.crl` over plain HTTP as well as HTTPS, without a redirect, because some clients fetch AIA and CDP URLs only over HTTP.

### Revocation lists expire

The CRLs are valid until **2027-11-04**. Regenerate them before that date, update the dates on the page,
rebuild `SHA256SUMS` and publish all three together:

```sh
sha256sum *.cer *.crl *.pem > SHA256SUMS
```

## License

[MIT](LICENSE)
