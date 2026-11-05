<?php
/*
 * Attestation JWT checks for attest.encedo.com (stateless).
 * Algorithms follow ../attest_verify/attest_verify.php and the firmware (api_system.c: attestation_jwt_sign, hem_canon_*, hem_pop_*):
 *  - JWT ES256 (raw r||s), header alg, typ, kid = hex SHA-1(04||x||y) (SHA-256 accepted for FW 1.4, DEV-471), jwk P-256
 *  - body: iss, aud, iat, exp, nonce, jti, device, key (with kid), pop (with pop_args)
 *  - pop.signature over "encedo-attest-pop:v1:sig" | aud | pubkey | nonce (uint16 BE length-prefixed fields) - checkable from the JWT alone
 *  - pop.mac (ECDH / KEM) needs the verifier's ephemeral secret - not checked here
 * Needs: PHP 8 with openssl + sodium; openssl CLI >= 3.5 only for Ed448 / ML-DSA PoP.
 */

const ISS = 'https://attest.encedo.com';
const TYP = 'encedo-attest+jwt';
const PFX_SIG = 'encedo-attest-pop:v1:sig';

const NIST = [
    'SECP256R1' => ['oid' => '1.2.840.10045.3.1.7', 'size' => 32, 'algo' => OPENSSL_ALGO_SHA256],
    'SECP384R1' => ['oid' => '1.3.132.0.34',        'size' => 48, 'algo' => OPENSSL_ALGO_SHA384],
    'SECP521R1' => ['oid' => '1.3.132.0.35',        'size' => 66, 'algo' => OPENSSL_ALGO_SHA512],
    'SECP256K1' => ['oid' => '1.3.132.0.10',        'size' => 32, 'algo' => OPENSSL_ALGO_SHA256],
];
const OKP = [   // raw public keys with a signature PoP
    'ED25519' => ['oid' => '1.3.101.112', 'len' => 32],
    'ED448'   => ['oid' => '1.3.101.113', 'len' => 57],
    'MLDSA44' => ['oid' => '2.16.840.1.101.3.4.3.17', 'len' => 1312],
    'MLDSA65' => ['oid' => '2.16.840.1.101.3.4.3.18', 'len' => 1952],
    'MLDSA87' => ['oid' => '2.16.840.1.101.3.4.3.19', 'len' => 2592],
];

// ------------------------------------------------------------------ encoding helpers
function b64url_dec(string $s): ?string {
    if (!preg_match('/^[A-Za-z0-9_-]*$/', $s)) return null;
    $r = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    return $r === false ? null : $r;
}
function b64url_enc(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function b64_dec(mixed $s): ?string { if (!is_string($s) || $s === '') return null; $r = base64_decode($s, true); return $r === false ? null : $r; }
function cn(string $d): string { return pack('n', strlen($d)) . $d; }

function der_len(int $n): string { if ($n < 128) return chr($n); $s = ''; while ($n > 0) { $s = chr($n & 0xff) . $s; $n >>= 8; } return chr(0x80 | strlen($s)) . $s; }
function der(int $tag, string $c): string { return chr($tag) . der_len(strlen($c)) . $c; }
function der_oid(string $oid): string {
    $p = array_map('intval', explode('.', $oid)); $b = chr(40 * $p[0] + $p[1]);
    for ($i = 2; $i < count($p); $i++) { $v = $p[$i]; $t = chr($v & 0x7f); $v >>= 7; while ($v > 0) { $t = chr(0x80 | ($v & 0x7f)) . $t; $v >>= 7; } $b .= $t; }
    return der(0x06, $b);
}
function pem(string $der, string $label): string { return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n"; }
function spki_pem(string $type, string $raw): string {
    $alg = isset(NIST[$type]) ? der_oid('1.2.840.10045.2.1') . der_oid(NIST[$type]['oid']) : der_oid(OKP[$type]['oid']);
    return pem(der(0x30, der(0x30, $alg) . der(0x03, "\x00" . $raw)), 'PUBLIC KEY');
}
function rs2der(string $raw): string {
    $n = intdiv(strlen($raw), 2); $out = '';
    foreach ([substr($raw, 0, $n), substr($raw, $n)] as $i) { $i = ltrim($i, "\0"); if ($i === '' || (ord($i[0]) & 0x80)) $i = "\0" . $i; $out .= der(0x02, $i); }
    return der(0x30, $out);
}

// ------------------------------------------------------------------ signatures
function ossl_bin(): string {
    $e = getenv('ENCEDO_OPENSSL'); if ($e) return $e;
    foreach (['C:\\Program Files\\Git\\ucrt64\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe'] as $c) if (is_file($c)) return $c;
    return 'openssl';
}
function ossl_verify_raw(string $spkiPem, string $msg, string $sig): bool {   // Ed448, ML-DSA: openssl CLI, pure signature over the message
    $f = []; foreach (['pub' => $spkiPem, 'msg' => $msg, 'sig' => $sig] as $k => $v) { $f[$k] = tempnam(sys_get_temp_dir(), 'att'); file_put_contents($f[$k], $v); }
    $cmd = escapeshellarg(ossl_bin()) . ' pkeyutl -verify -pubin -inkey ' . escapeshellarg($f['pub']) . ' -rawin -in ' . escapeshellarg($f['msg']) . ' -sigfile ' . escapeshellarg($f['sig']);
    $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $rc = 1;
    if (is_resource($p)) { stream_get_contents($pipes[1]); stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]); $rc = proc_close($p); }
    foreach ($f as $x) @unlink($x);
    return $rc === 0;
}
function verify_sig(string $type, string $pubRaw, string $msg, string $sig): bool {
    if (isset(NIST[$type])) {
        if (strlen($sig) !== 2 * NIST[$type]['size']) return false;
        $k = @openssl_pkey_get_public(spki_pem($type, $pubRaw));
        return $k !== false && openssl_verify($msg, rs2der($sig), $k, NIST[$type]['algo']) === 1;
    }
    if ($type === 'ED25519') return strlen($pubRaw) === 32 && strlen($sig) === 64 && sodium_crypto_sign_verify_detached($sig, $msg, $pubRaw);
    if (isset(OKP[$type])) return strlen($pubRaw) === OKP[$type]['len'] && ossl_verify_raw(spki_pem($type, $pubRaw), $msg, $sig);
    return false;
}

// ------------------------------------------------------------------ the check
// Returns: ok (the JWT itself is valid), expired, skid1 / skid256 (hex of 04||x||y of jwk), point (04||x||y), hdr, body, pop [method, result], why (internal only, never sent)
function attest_check(string $jwt, ?int $now = null): array {
    $now ??= time();
    $r = ['ok' => false, 'expired' => false, 'skid1' => null, 'skid256' => null, 'point' => null, 'hdr' => null, 'body' => null, 'pop' => ['none', ''], 'why' => ''];
    $bad = function (string $why) use (&$r) { $r['ok'] = false; $r['why'] = $why; return $r; };

    $jwt = trim($jwt);
    $j = json_decode($jwt, true); if (is_array($j) && is_string($j['attestation'] ?? null)) $jwt = trim($j['attestation']);   // reply {"attestation": "<JWT>"} pasted as is
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return $bad('not 3 segments');
    $h = b64url_dec($parts[0]); $b = b64url_dec($parts[1]); $sig = b64url_dec($parts[2]);
    $hdr = $h === null ? null : json_decode($h, true); $body = $b === null ? null : json_decode($b, true);
    $r['hdr'] = is_array($hdr) ? $hdr : null; $r['body'] = is_array($body) ? $body : null;
    if (!is_array($hdr) || !is_array($body) || $sig === null) return $bad('segments not base64url JSON');

    // level 1a: header and the device signature
    if (($hdr['alg'] ?? null) !== 'ES256') return $bad('alg');
    if (($hdr['typ'] ?? null) !== TYP) return $bad('typ');
    $jwk = $hdr['jwk'] ?? null;
    if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') return $bad('jwk');
    $x = b64url_dec((string)($jwk['x'] ?? '')); $y = b64url_dec((string)($jwk['y'] ?? ''));
    if ($x === null || $y === null || strlen($x) !== 32 || strlen($y) !== 32) return $bad('jwk x/y');
    $point = "\x04" . $x . $y;
    $r['skid1'] = sha1($point); $r['skid256'] = hash('sha256', $point); $r['point'] = $point;
    $kid = strtolower((string)($hdr['kid'] ?? ''));
    if ($kid !== $r['skid1'] && $kid !== $r['skid256']) return $bad('header kid != hash of jwk');
    if (!verify_sig('SECP256R1', $point, $parts[0] . '.' . $parts[1], $sig)) return $bad('JWT signature');

    // level 1b: claims
    if (($body['iss'] ?? null) !== ISS) return $bad('iss');
    $aud = $body['aud'] ?? null;
    if (!is_string($aud) || !preg_match('/^[\x20-\x7e]{1,64}$/', $aud)) return $bad('aud');
    $nonce = b64_dec($body['nonce'] ?? null);
    if ($nonce === null || strlen($nonce) < 32 || strlen($nonce) > 64) return $bad('nonce');
    $iat = $body['iat'] ?? null; $exp = $body['exp'] ?? null;
    if (!is_int($iat) || !is_int($exp) || $exp <= $iat) return $bad('iat / exp');
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string)($body['jti'] ?? ''))) return $bad('jti');
    $dev = $body['device'] ?? null;
    if (!is_array($dev) || !is_string($dev['hwv'] ?? null) || !is_string($dev['fwv'] ?? null)) return $bad('device');

    // key claim and PoP
    $key = $body['key'] ?? null; $pop = $body['pop'] ?? null;
    if ($key !== null) {
        if (!is_array($key) || !preg_match('/^[0-9a-f]{32}$/', (string)($key['kid'] ?? '')) || !is_string($key['type'] ?? null) || !is_array($key['modes'] ?? null)) return $bad('key');
    }
    if ($pop !== null) {
        if (!is_array($pop) || !is_array($key)) return $bad('pop without key');
        if (isset($pop['signature'])) {
            $type = $key['type']; $pub = b64_dec($key['pubkey']['primary'] ?? null); $s = b64_dec($pop['signature']);
            if ($pub === null || $s === null || (!isset(NIST[$type]) && !isset(OKP[$type]))) return $bad('pop.signature input');
            if (!verify_sig($type, $pub, cn(PFX_SIG) . cn($aud) . cn($pub) . cn($nonce), $s)) return $bad('pop.signature');
            $r['pop'] = ['signature', 'ok'];
        } elseif (isset($pop['mac'])) {
            $m = b64_dec($pop['mac']);
            if ($m === null || strlen($m) !== 32) return $bad('pop.mac');
            $r['pop'] = ['mac', 'not checked'];
        } else return $bad('pop');
    }

    $r['ok'] = true;
    $r['expired'] = $now > $exp;
    return $r;
}
