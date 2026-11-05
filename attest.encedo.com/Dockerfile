# attest.encedo.com - stateless attestation JWT validation (DEV-498)
# PHP image: openssl, sodium and pdo_sqlite are built in; the openssl CLI (>= 3.5) checks Ed448 / ML-DSA PoP signatures.
FROM php:8.4-cli-alpine
RUN apk add --no-cache openssl && openssl version
WORKDIR /app
COPY lib/ lib/
COPY public/ public/
COPY tools/build_index.php tools/build_index.php
COPY tools/sync_pki.php tools/sync_pki.php
# read-only data mounted at run time: /data/pki/*.pem + /data/crl/*.crl.pem (Encedo PKI, tools/sync_pki.php), /data/data/index.sqlite (tools/build_index.php)
ENV ATTEST_DATA=/data ENCEDO_OPENSSL=/usr/bin/openssl
USER nobody
EXPOSE 8080
# the PHP built-in server, one process; TLS, rate limiting and request logging policy in the reverse proxy in front
CMD ["php", "-d", "expose_php=0", "-d", "display_errors=0", "-S", "0.0.0.0:8080", "public/index.php"]
