# attest_verify.php: weryfikator atestacji Encedo HEM

Sprawdza token JWT zwracany przez `POST /api/system/config/attestation`. Odwzorowuje dokładnie algorytmy firmware:
- `attestation_jwt_sign`,
- `hem_canon_*`,
- `hem_pop_*` w `api_system.c`.

## Format (FW 1.3.x po reworku DEV-423)

- Podpis PoP: `"encedo-attest-pop:v1:sig" ‖ aud ‖ pubkey ‖ nonce`, czyli ta sama kolejność co w ECDH i KEM. Wcześniej było `aud ‖ nonce ‖ pubkey`.
- `pop_args` nie zawiera `verifier_eph_pub_alg` ani `ciphertext_alg`. Krzywą i poziom wyznacza klucz (KID).
- PoP działa tylko dla klucza z częścią prywatną. Klucz zaimportowany jako sam klucz publiczny oraz klucz symetryczny z `pop_args` dają 400.
- Blok `device` nie zawiera `fws` ani `bls`. Zawiera `fw_cid`/`bl_cid`, ale tylko w buildach wydaniowych.
- Klucz symetryczny (SHA2-\*, SHA3-\*, AES\*) ma blok `key` bez `pubkey`. Pole `modes` ma wartość `HMAC` albo `AES`.

## Wymagania

- PHP 8 z rozszerzeniami `hash` i `json`. Rozszerzenia `openssl` ani `sodium` **nie są potrzebne**.
- `openssl` CLI w wersji ≥ 3.5, wymaganej dla ML-DSA i ML-KEM. Domyślnie skrypt używa `C:\Program Files\Git\ucrt64\bin\openssl.exe` z Git for Windows. Inną ścieżkę ustawia zmienna `ENCEDO_OPENSSL`.

## Użycie

### 1. Przygotowanie żądania

`prepare` generuje `nonce`, a dla PoP także klucz efemeryczny ECDH albo ciphertext KEM. Zapisuje stan potrzebny do weryfikacji.

```
php attest_verify.php prepare --aud <verifier-id> --state st.json --out req.json        # sama atestacja urządzenia
php attest_verify.php prepare --aud <id> --kid <hex KID> --metadata --pop sig  --state st.json --out req.json      # ExDSA: NIST, ED25519/ED448, MLDSA*
php attest_verify.php prepare --aud <id> --kid <hex KID> --pop ecdh --type CURVE25519 --state st.json --out req.json  # ECDH: SECP*/CURVE25519/CURVE448
php attest_verify.php prepare --aud <id> --kid <hex KID> --pop kem  --type MLKEM768 --pubkey <base64 klucza publicznego z /keymgmt> --state st.json --out req.json
```

### 2. Wysłanie żądania

`req.json` wysyłasz jako treść `POST /api/system/config/attestation`. Odpowiedź (`{"attestation": "<JWT>"}` od FW 1.3.0, wcześniej sam JWT) zapisujesz do pliku, np. `token.jwt`; `verify` przyjmuje obie postaci.

### 3. Weryfikacja

```
php attest_verify.php verify --state st.json --jwt token.jwt
```

Sprawdzane są:
- **nagłówek:** `ES256`, `typ`, `jwk` P-256;
- **SKID:** wyliczany jako SHA-1(`04‖x‖y`) z `jwk`, a nie brany z pola `kid`;
- **podpis JWT;**
- **pola tokena:** `aud`, `nonce`, `iat`/`exp` (tolerancja `--leeway`, domyślnie 300 s), `jti` (UUID v4), blok `device`;
- **przy `--kid`:** blok `key` i PoP (`pop.signature` albo `pop.mac`).

Na końcu weryfikator wypisuje **SKID urządzenia**. Ten SKID (a nie cały JWT) przekazuje się producentowi, który porównuje go z SKID certyfikatu urządzenia.

### Selftest

```
php attest_verify.php selftest
```

Symuluje stronę urządzenia dla wszystkich typów kluczy (19 przypadków). Każdy przypadek ma test pozytywny i negatywny (zmieniony `aud`). Sprawdza spójność samego weryfikatora z algorytmem firmware. Nie zastępuje testu na urządzeniu.

## Stan (`st.json`)

Plik zawiera `nonce`, `aud` oraz sekrety efemeryczne: klucz prywatny ECDH albo shared secret KEM. Jest potrzebny tylko do `verify`, a po weryfikacji należy go usunąć.

## Kody wyjścia

- `0`: wszystko OK;
- `1`: któraś kontrola się nie powiodła;
- `2`: błąd użycia albo wywołania `openssl`.
