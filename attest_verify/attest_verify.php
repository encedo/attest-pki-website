<?php
/*
 * Encedo HEM - attestation JWT verifier (POST /api/system/config/attestation)
 *
 * Mirrors the firmware (api_system.c: hem_canon_*, hem_pop_*, attestation_jwt_sign):
 *  - JWT ES256 signed by ATECC608 slot 0, header: alg, typ, kid = hex SHA-1(04||x||y), jwk (P-256, x/y base64url)
 *  - binary fields in the body: standard base64 (API convention), KID: hex
 *  - PoP canonical message: length-prefixed (uint16 BE) fields
 *      sig : "encedo-attest-pop:v1:sig"  | aud | pubkey | nonce          (DEV-423 rework: was aud | nonce | pubkey)
 *      ecdh: "encedo-attest-pop:v1:ecdh" | aud | pubkey || nonce | eph_pub          (info = first 3 fields)
 *      kem : "encedo-attest-pop:v1:kem"  | aud | pubkey || nonce | SHA-256(ct)      (info = first 3 fields)
 *    mac = HMAC-SHA256(HKDF-SHA256(ikm=shared_secret, salt=nonce, info), canonical)
 *  - pop_args: {} = signature, {verifier_eph_pub} = ECDH-MAC, {ciphertext} = KEM-MAC; the curve / level comes from the key
 *    (verifier_eph_pub_alg / ciphertext_alg removed). PoP needs a private key: public-key-only imports and symmetric keys -> 400
 *  - device block: hwv, fwv, blv, cc_mode, policy, fw_cid / bl_cid (release builds only); fws / bls removed
 *  - symmetric keys (SHA2-*, SHA3-*, AES*): key block without pubkey, modes HMAC / AES
 *
 * Needs: PHP 8 with 'hash' and 'json' only; all public-key operations are done by the openssl CLI (>= 3.5 for ML-DSA/ML-KEM).
 *
 * Usage:
 *   php attest_verify.php prepare --aud <id> [--kid <hex>] [--metadata] [--pop none|sig|ecdh|kem]
 *                                 [--type <KEYTYPE>] [--pubkey <base64 device key public key>]
 *                                 --state state.json [--out request.json]
 *   php attest_verify.php verify  --state state.json --jwt <token|file> [--leeway 300]
 *   php attest_verify.php selftest
 *
 * Environment: ENCEDO_OPENSSL = path to openssl.exe (default: Git for Windows ucrt64 openssl, then "openssl" in PATH)
 */

const PFX_SIG  = 'encedo-attest-pop:v1:sig';
const PFX_ECDH = 'encedo-attest-pop:v1:ecdh';
const PFX_KEM  = 'encedo-attest-pop:v1:kem';

const NIST = [
    'SECP256R1' => ['oid' => '1.2.840.10045.3.1.7', 'size' => 32, 'hash' => 'sha256', 'ossl' => 'P-256'],
    'SECP384R1' => ['oid' => '1.3.132.0.34',        'size' => 48, 'hash' => 'sha384', 'ossl' => 'P-384'],
    'SECP521R1' => ['oid' => '1.3.132.0.35',        'size' => 66, 'hash' => 'sha512', 'ossl' => 'P-521'],
    'SECP256K1' => ['oid' => '1.3.132.0.10',        'size' => 32, 'hash' => 'sha256', 'ossl' => 'secp256k1'],
];
const OKP = [   // raw public keys, OID only (no parameters)
    'CURVE25519' => ['oid' => '1.3.101.110', 'len' => 32,   'ossl' => 'X25519'],
    'CURVE448'   => ['oid' => '1.3.101.111', 'len' => 56,   'ossl' => 'X448'],
    'ED25519'    => ['oid' => '1.3.101.112', 'len' => 32,   'ossl' => 'ED25519'],
    'ED448'      => ['oid' => '1.3.101.113', 'len' => 57,   'ossl' => 'ED448'],
    'MLDSA44'    => ['oid' => '2.16.840.1.101.3.4.3.17', 'len' => 1312, 'ossl' => 'ML-DSA-44'],
    'MLDSA65'    => ['oid' => '2.16.840.1.101.3.4.3.18', 'len' => 1952, 'ossl' => 'ML-DSA-65'],
    'MLDSA87'    => ['oid' => '2.16.840.1.101.3.4.3.19', 'len' => 2592, 'ossl' => 'ML-DSA-87'],
    'MLKEM512'   => ['oid' => '2.16.840.1.101.3.4.4.1',  'len' => 800,  'ossl' => 'ML-KEM-512'],
    'MLKEM768'   => ['oid' => '2.16.840.1.101.3.4.4.2',  'len' => 1184, 'ossl' => 'ML-KEM-768'],
    'MLKEM1024'  => ['oid' => '2.16.840.1.101.3.4.4.3',  'len' => 1568, 'ossl' => 'ML-KEM-1024'],
];
const SIG_TYPES  = ['ED25519', 'ED448', 'MLDSA44', 'MLDSA65', 'MLDSA87'];     // + NIST with ExDSA
const ECDH_TYPES = ['SECP256R1', 'SECP384R1', 'SECP521R1', 'SECP256K1', 'CURVE25519', 'CURVE448'];
const KEM_TYPES  = ['MLKEM512', 'MLKEM768', 'MLKEM1024'];

// ------------------------------------------------------------------ helpers
function fail(string $m): void { fwrite(STDERR, "ERROR: $m\n"); exit(2); }
function b64url_dec(string $s): string { $s = strtr($s, '-_', '+/'); $p = strlen($s) % 4; if ($p) $s .= str_repeat('=', 4 - $p); $r = base64_decode($s, true); if ($r === false) fail('bad base64url'); return $r; }
function b64url_enc(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function b64_dec(string $s, string $what): string { $r = base64_decode($s, true); if ($r === false) fail("bad base64 in $what"); return $r; }
function cn(string $d): string { return pack('n', strlen($d)) . $d; }

function der_len(int $n): string { if ($n < 128) return chr($n); $s = ''; while ($n > 0) { $s = chr($n & 0xff) . $s; $n >>= 8; } return chr(0x80 | strlen($s)) . $s; }
function der(int $tag, string $c): string { return chr($tag) . der_len(strlen($c)) . $c; }
function der_oid(string $oid): string {
    $p = array_map('intval', explode('.', $oid)); $b = chr(40 * $p[0] + $p[1]);
    for ($i = 2; $i < count($p); $i++) { $v = $p[$i]; $t = chr($v & 0x7f); $v >>= 7; while ($v > 0) { $t = chr(0x80 | ($v & 0x7f)) . $t; $v >>= 7; } $b .= $t; }
    return der(0x06, $b);
}
function pem(string $der, string $label): string { return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n"; }
function spki(string $type, string $raw): string {
    if (isset(NIST[$type])) $alg = der_oid('1.2.840.10045.2.1') . der_oid(NIST[$type]['oid']);
    elseif (isset(OKP[$type])) $alg = der_oid(OKP[$type]['oid']);
    else fail("unsupported key type $type");
    return pem(der(0x30, der(0x30, $alg) . der(0x03, "\x00" . $raw)), 'PUBLIC KEY');
}
function rs2der(string $raw): string {
    $n = intdiv(strlen($raw), 2); $out = '';
    foreach ([substr($raw, 0, $n), substr($raw, $n)] as $i) { $i = ltrim($i, "\0"); if ($i === '' || (ord($i[0]) & 0x80)) $i = "\0" . $i; $out .= der(0x02, $i); }
    return der(0x30, $out);
}
function der2rs(string $der, int $size): string {   // ECDSA DER -> raw r||s (selftest only)
    $p = 2; if (ord($der[1]) & 0x80) $p += ord($der[1]) & 0x7f; $out = '';
    for ($k = 0; $k < 2; $k++) { $l = ord($der[$p + 1]); $v = ltrim(substr($der, $p + 2, $l), "\0"); $out .= str_pad($v, $size, "\0", STR_PAD_LEFT); $p += 2 + $l; }
    return $out;
}
function compress_point(string $u): string { $n = intdiv(strlen($u) - 1, 2); return chr(2 | (ord($u[strlen($u) - 1]) & 1)) . substr($u, 1, $n); }

// ------------------------------------------------------------------ openssl CLI
function ossl_bin(): string {
    $e = getenv('ENCEDO_OPENSSL'); if ($e) return $e;
    foreach (['C:\\Program Files\\Git\\ucrt64\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe'] as $c) if (is_file($c)) return $c;
    return 'openssl';
}
function tmpf(?string $content = null): string { $f = tempnam(sys_get_temp_dir(), 'eat'); if ($content !== null) file_put_contents($f, $content); $GLOBALS['TMP'][] = $f; return $f; }
register_shutdown_function(function () { foreach ($GLOBALS['TMP'] ?? [] as $f) @unlink($f); });
function ossl(array $args, ?string &$out = null): int {
    $cmd = escapeshellarg(ossl_bin()); foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) fail('cannot run openssl');
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
    return proc_close($p);
}
function ossl_ok(array $args): string { $o = null; if (ossl($args, $o) !== 0) fail('openssl ' . implode(' ', $args) . "\n$o"); return $o; }

function verify_sig(string $type, string $pubRaw, string $msg, string $sigRaw): bool {
    $pub = tmpf(spki($type, $pubRaw)); $m = tmpf($msg);
    if (isset(NIST[$type])) {
        $s = tmpf(rs2der($sigRaw));
        return ossl(['dgst', '-' . NIST[$type]['hash'], '-verify', $pub, '-signature', $s, $m]) === 0;
    }
    $s = tmpf($sigRaw);
    return ossl(['pkeyutl', '-verify', '-pubin', '-inkey', $pub, '-rawin', '-in', $m, '-sigfile', $s]) === 0;
}
function gen_key(string $type): string {   // returns private key PEM
    $f = tmpf();
    if (isset(NIST[$type])) ossl_ok(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:' . NIST[$type]['ossl'], '-out', $f]);
    else ossl_ok(['genpkey', '-algorithm', OKP[$type]['ossl'], '-out', $f]);
    return file_get_contents($f);
}
function pub_raw_from_priv(string $type, string $privPem): string {   // firmware format: NIST compressed, others raw
    $d = tmpf(); ossl_ok(['pkey', '-in', tmpf($privPem), '-pubout', '-outform', 'DER', '-out', $d]); $der = file_get_contents($d);
    if (isset(NIST[$type])) return compress_point(substr($der, -(1 + 2 * NIST[$type]['size'])));
    return substr($der, -OKP[$type]['len']);
}
function derive(string $type, string $privPem, string $peerRaw): string {
    $ss = tmpf(); ossl_ok(['pkeyutl', '-derive', '-inkey', tmpf($privPem), '-peerkey', tmpf(spki($type, $peerRaw)), '-out', $ss]);
    return file_get_contents($ss);
}
function canon_sig(string $aud, string $nonce, string $pub): string { return cn(PFX_SIG) . cn($aud) . cn($pub) . cn($nonce); }   // one order for all PoP: prefix | aud | pubkey | nonce
function pop_mac(string $pfx, string $ss, string $aud, string $nonce, string $pub, string $last): string {
    $info = cn($pfx) . cn($aud) . cn($pub);
    $key  = hash_hkdf('sha256', $ss, 32, $info, $nonce);
    return hash_hmac('sha256', $info . cn($nonce) . cn($last), $key, true);
}

// ------------------------------------------------------------------ prepare
function cmd_prepare(array $o): void {
    $aud = $o['aud'] ?? fail('--aud required'); $pop = $o['pop'] ?? 'none';
    $st = ['aud' => $aud, 'nonce' => base64_encode(random_bytes(32)), 'kid' => $o['kid'] ?? null, 'pop' => $pop];
    $req = ['nonce' => $st['nonce'], 'aud' => $aud];
    if ($st['kid']) { if (!preg_match('/^[0-9a-fA-F]{32}$/', $st['kid'])) fail('--kid must be 32 hex chars'); $req['kid'] = strtolower($st['kid']); }
    if (isset($o['metadata'])) $req['include_metadata'] = true;
    if ($pop !== 'none') {
        if (!$st['kid']) fail('PoP needs --kid');
        if ($pop === 'sig') {
            $req['pop_args'] = new stdClass();                    // {} - ExDSA keys
        } elseif ($pop === 'ecdh') {
            $type = strtoupper($o['type'] ?? fail('--type required for ecdh'));
            if (!in_array($type, ECDH_TYPES, true)) fail('ecdh type: ' . implode('|', ECDH_TYPES));
            $priv = gen_key($type); $pub = pub_raw_from_priv($type, $priv);
            $st += ['type' => $type, 'eph_priv_pem' => $priv, 'eph_pub' => base64_encode($pub)];
            $req['pop_args'] = ['verifier_eph_pub' => base64_encode($pub)];      // --type only selects the curve of the ephemeral key
        } elseif ($pop === 'kem') {
            $type = strtoupper($o['type'] ?? fail('--type required for kem'));
            if (!in_array($type, KEM_TYPES, true)) fail('kem type: ' . implode('|', KEM_TYPES));
            $devPub = b64_dec($o['pubkey'] ?? fail('--pubkey (device ML-KEM public key, base64) required for kem'), '--pubkey');
            $ct = tmpf(); $ss = tmpf();
            ossl_ok(['pkeyutl', '-encap', '-pubin', '-inkey', tmpf(spki($type, $devPub)), '-out', $ct, '-secret', $ss]);
            $st += ['type' => $type, 'kem_ct' => base64_encode(file_get_contents($ct)), 'kem_ss' => base64_encode(file_get_contents($ss))];
            $req['pop_args'] = ['ciphertext' => $st['kem_ct']];
        } else fail('--pop none|sig|ecdh|kem');
    }
    $state = $o['state'] ?? fail('--state required');
    file_put_contents($state, json_encode($st, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    $j = json_encode($req, JSON_UNESCAPED_SLASHES);
    if (isset($o['out'])) file_put_contents($o['out'], $j);
    echo $j, "\n";
    if (empty($o['silent'])) fwrite(STDERR, "state saved to $state (keep it until 'verify'; it holds ephemeral secrets)\n");
}

// ------------------------------------------------------------------ verify
// $quiet: 0 = print all checks, 1 = print failures only, 2 = silent
function verify_token(string $jwt, array $st, int $leeway = 300, int $quiet = 0): bool {
    $ok = true;
    $chk = function (string $name, bool $res, string $info = '') use (&$ok, $quiet) { if (!$res) $ok = false; if ($quiet === 0 || ($quiet === 1 && !$res)) printf("  [%s] %s%s\n", $res ? 'PASS' : 'FAIL', $name, $info !== '' ? " - $info" : ''); };
    $parts = explode('.', trim($jwt));
    if (count($parts) !== 3) { $chk('JWT compact serialization (3 segments)', false); return false; }
    $hdr = json_decode(b64url_dec($parts[0]), true); $body = json_decode(b64url_dec($parts[1]), true); $sig = b64url_dec($parts[2]);
    $chk('header/body are JSON', is_array($hdr) && is_array($body));
    if (!is_array($hdr) || !is_array($body)) return false;

    // 1. header + device signature
    $chk('alg = ES256', ($hdr['alg'] ?? '') === 'ES256');
    $chk('typ = encedo-attest+jwt', ($hdr['typ'] ?? '') === 'encedo-attest+jwt');
    $jwk = $hdr['jwk'] ?? []; $x = isset($jwk['x']) ? b64url_dec($jwk['x']) : ''; $y = isset($jwk['y']) ? b64url_dec($jwk['y']) : '';
    $chk('jwk EC P-256, x/y 32B', ($jwk['kty'] ?? '') === 'EC' && ($jwk['crv'] ?? '') === 'P-256' && strlen($x) === 32 && strlen($y) === 32);
    $point = "\x04" . $x . $y; $skid = sha1($point);
    $chk('header kid = SHA-1(04||x||y) from jwk', strtolower($hdr['kid'] ?? '') === $skid, "SKID $skid");
    $chk('JWT signature (ES256, jwk)', strlen($sig) === 64 && verify_sig('SECP256R1', $point, $parts[0] . '.' . $parts[1], $sig));

    // 2. claims
    $chk('aud matches request', ($body['aud'] ?? null) === $st['aud']);
    $chk('nonce matches request', ($body['nonce'] ?? null) === $st['nonce']);
    $iat = $body['iat'] ?? 0; $exp = $body['exp'] ?? 0; $now = time();
    $chk('exp > iat', $exp > $iat, "iat $iat, exp $exp, device clock offset " . ($iat - $now) . 's');
    $chk('token not expired (device clock vs local, leeway ' . $leeway . 's)', $now <= $exp + $leeway && $iat <= $now + $leeway);
    $chk('jti is UUID v4', (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $body['jti'] ?? ''), $body['jti'] ?? '');
    $dev = $body['device'] ?? [];
    $chk('device block', isset($dev['hwv'], $dev['fwv']), ($dev['hwv'] ?? '?') . ' / ' . ($dev['fwv'] ?? '?') . ' / ' . ($dev['blv'] ?? '?')
        . (isset($dev['fw_cid']) ? ' / fw_cid ' . $dev['fw_cid'] : ' / no fw_cid (R&D build)'));
    $chk('device block without fws / bls (removed in FW 1.3.x)', !isset($dev['fws']) && !isset($dev['bls']));

    // 3. key + PoP
    if (!empty($st['kid'])) {
        $key = $body['key'] ?? null;
        $chk('key block present', is_array($key));
        if (!is_array($key)) return $ok;
        $chk('key.kid matches request', strtolower($key['kid'] ?? '') === strtolower($st['kid']), ($key['type'] ?? '?') . ' modes ' . implode(',', $key['modes'] ?? []));
        $chk('key.modes not empty', !empty($key['modes']));
        $type = $key['type'] ?? '';
        if (!isset(NIST[$type]) && !isset(OKP[$type])) {   // symmetric key: no public key, no PoP
            $chk("symmetric key ($type): no pubkey, no pop", !isset($key['pubkey']) && !isset($body['pop']), 'properties ' . json_encode($key['properties'] ?? null));
            if ($quiet === 0) printf("\n  Device SKID for the manufacturer check: %s\n", $skid);
            return $ok;
        }
        $pub = b64_dec($key['pubkey']['primary'] ?? '', 'key.pubkey.primary');
        $pop = $body['pop'] ?? null;
        if (($st['pop'] ?? 'none') === 'none') {
            $chk('no pop requested -> no pop in token', $pop === null);
        } elseif ($st['pop'] === 'sig') {
            $s = b64_dec($pop['signature'] ?? '', 'pop.signature');
            $chk("pop.signature ($type)", $s !== '' && verify_sig($type, $pub, canon_sig($st['aud'], base64_decode($st['nonce']), $pub), $s));
        } elseif ($st['pop'] === 'ecdh') {
            $m = b64_dec($pop['mac'] ?? '', 'pop.mac');
            $ss = derive($st['type'], $st['eph_priv_pem'], $pub);
            $exp_mac = pop_mac(PFX_ECDH, $ss, $st['aud'], base64_decode($st['nonce']), $pub, base64_decode($st['eph_pub']));
            $chk("pop.mac ECDH ($type)", $m !== '' && hash_equals($exp_mac, $m));
        } elseif ($st['pop'] === 'kem') {
            $m = b64_dec($pop['mac'] ?? '', 'pop.mac');
            $exp_mac = pop_mac(PFX_KEM, base64_decode($st['kem_ss']), $st['aud'], base64_decode($st['nonce']), $pub, hash('sha256', base64_decode($st['kem_ct']), true));
            $chk("pop.mac KEM ($type)", $m !== '' && hash_equals($exp_mac, $m));
        }
    }
    if ($quiet === 0) printf("\n  Device SKID for the manufacturer check: %s\n", $skid);
    return $ok;
}
function cmd_verify(array $o): void {
    $st = json_decode(file_get_contents($o['state'] ?? fail('--state required')), true) ?: fail('bad state file');
    $jwt = $o['jwt'] ?? fail('--jwt required'); if (is_file($jwt)) $jwt = file_get_contents($jwt);
    $j = json_decode(trim($jwt), true); if (is_array($j) && isset($j['attestation'])) $jwt = $j['attestation'];   // FW 1.3.0 reply {"attestation": "<JWT>"} or the bare JWT
    echo "Verifying attestation JWT\n";
    $ok = verify_token($jwt, $st, (int)($o['leeway'] ?? 300));
    echo $ok ? "\nRESULT: OK\n" : "\nRESULT: FAILED\n";
    exit($ok ? 0 : 1);
}

// ------------------------------------------------------------------ selftest (simulates the firmware side)
function device_token(string $attPriv, array $req, ?array $dk): string {
    $attPub = "\x04" . substr(pub_raw_from_der_uncomp($attPriv), 1);
    $hdr = ['alg' => 'ES256', 'typ' => 'encedo-attest+jwt', 'kid' => sha1($attPub),
            'jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => b64url_enc(substr($attPub, 1, 32)), 'y' => b64url_enc(substr($attPub, 33, 32))]];
    $now = time();
    $body = ['iss' => 'https://attest.encedo.com', 'aud' => $req['aud'], 'iat' => $now, 'exp' => $now + 300,
             'nonce' => $req['nonce'], 'jti' => sprintf('%08x-%04x-4%03x-%x%03x-%012x', random_int(0, 0xffffffff), random_int(0, 0xffff), random_int(0, 0xfff), random_int(8, 11), random_int(0, 0xfff), random_int(0, 0xffffffffffff)),
             'device' => ['hwv' => 'selftest', 'fwv' => 'Encedo nGINE FW v1.3.0', 'blv' => 'bl', 'cc_mode' => 0, 'policy' => []]];
    if ($dk) {
        $type = $dk['type']; $pub = pub_raw_from_priv($type, $dk['priv']); $nonce = base64_decode($req['nonce']);
        $modes = in_array($type, KEM_TYPES) ? ['MLKEM'] : (strpos($type, 'MLDSA') === 0 ? ['MLDSA'] : (in_array($type, ['CURVE25519', 'CURVE448']) || isset($req['pop_args']['verifier_eph_pub']) ? ['ECDH'] : ['ExDSA']));
        $body['key'] = ['type' => $type, 'modes' => $modes,
                        'pubkey' => ['primary' => base64_encode($pub)], 'kid' => $req['kid']];
        $pa = $req['pop_args'] ?? null;
        if ($pa !== null) {
            if (isset($pa['verifier_eph_pub'])) {
                $ss = derive($type, $dk['priv'], base64_decode($pa['verifier_eph_pub']));
                $body['pop'] = ['mac' => base64_encode(pop_mac(PFX_ECDH, $ss, $req['aud'], $nonce, $pub, base64_decode($pa['verifier_eph_pub'])))];
            } elseif (isset($pa['ciphertext'])) {
                $ss = tmpf(); ossl_ok(['pkeyutl', '-decap', '-inkey', tmpf($dk['priv']), '-in', tmpf(base64_decode($pa['ciphertext'])), '-secret', $ss]);
                $body['pop'] = ['mac' => base64_encode(pop_mac(PFX_KEM, file_get_contents($ss), $req['aud'], $nonce, $pub, hash('sha256', base64_decode($pa['ciphertext']), true)))];
            } else {
                $msg = tmpf(canon_sig($req['aud'], $nonce, $pub)); $sf = tmpf();
                if (isset(NIST[$type])) { ossl_ok(['dgst', '-' . NIST[$type]['hash'], '-sign', tmpf($dk['priv']), '-out', $sf, $msg]); $s = der2rs(file_get_contents($sf), NIST[$type]['size']); }
                else { ossl_ok(['pkeyutl', '-sign', '-inkey', tmpf($dk['priv']), '-rawin', '-in', $msg, '-out', $sf]); $s = file_get_contents($sf); }
                $body['pop'] = ['signature' => base64_encode($s)];
            }
        }
    }
    $si = b64url_enc(json_encode($hdr, JSON_UNESCAPED_SLASHES)) . '.' . b64url_enc(json_encode($body, JSON_UNESCAPED_SLASHES));
    $sf = tmpf(); ossl_ok(['dgst', '-sha256', '-sign', tmpf($attPriv), '-out', $sf, tmpf($si)]);
    return $si . '.' . b64url_enc(der2rs(file_get_contents($sf), 32));
}
function pub_raw_from_der_uncomp(string $privPem): string { $d = tmpf(); ossl_ok(['pkey', '-in', tmpf($privPem), '-pubout', '-outform', 'DER', '-out', $d]); return substr(file_get_contents($d), -65); }

function cmd_selftest(): void {
    echo 'openssl: ', trim(ossl_ok(['version'])), "\n";
    $att = gen_key('SECP256R1');
    $cases = [['none', null], ['sig', 'SECP256R1'], ['sig', 'SECP384R1'], ['sig', 'SECP521R1'], ['sig', 'SECP256K1'], ['sig', 'ED25519'], ['sig', 'ED448'],
              ['sig', 'MLDSA44'], ['sig', 'MLDSA65'], ['sig', 'MLDSA87'],
              ['ecdh', 'SECP256R1'], ['ecdh', 'SECP384R1'], ['ecdh', 'SECP521R1'], ['ecdh', 'SECP256K1'], ['ecdh', 'CURVE25519'], ['ecdh', 'CURVE448'],
              ['kem', 'MLKEM512'], ['kem', 'MLKEM768'], ['kem', 'MLKEM1024']];
    $all = true;
    foreach ($cases as [$pop, $type]) {
        $kid = $type ? bin2hex(random_bytes(16)) : null; $dk = $type ? ['type' => $type, 'priv' => gen_key($type)] : null;
        $stf = tmpf(); $o = ['aud' => 'selftest', 'pop' => $type ? $pop : 'none', 'state' => $stf, 'silent' => true];
        if ($kid) $o['kid'] = $kid;
        if ($pop === 'ecdh' || $pop === 'kem') $o['type'] = $type;
        if ($pop === 'kem') $o['pubkey'] = base64_encode(pub_raw_from_priv($type, $dk['priv']));
        ob_start(); cmd_prepare($o); $req = json_decode(trim(ob_get_clean()), true);
        $st = json_decode(file_get_contents($stf), true);
        $good = verify_token(device_token($att, $req, $dk), $st, 300, 1);
        // negative: tamper the token body -> must fail
        $t = explode('.', device_token($att, $req, $dk)); $b = json_decode(b64url_dec($t[1]), true); $b['aud'] = 'tampered';
        $bad = !verify_token($t[0] . '.' . b64url_enc(json_encode($b)) . '.' . $t[2], $st, 300, 2);
        printf("%-5s %-11s positive:%s  negative:%s\n", $pop, $type ?? '-', $good ? 'OK' : 'FAIL', $bad ? 'OK' : 'FAIL');
        $all = $all && $good && $bad;
    }
    echo $all ? "SELFTEST OK\n" : "SELFTEST FAILED\n";
    exit($all ? 0 : 1);
}

// ------------------------------------------------------------------ main
$cmd = $argv[1] ?? ''; $o = [];
for ($i = 2; $i < $argc; $i++) {
    if (substr($argv[$i], 0, 2) !== '--') fail("unexpected argument {$argv[$i]}");
    $k = substr($argv[$i], 2);
    if ($k === 'metadata') { $o[$k] = true; continue; }
    $o[$k] = $argv[++$i] ?? fail("missing value for --$k");
}
switch ($cmd) {
    case 'prepare':  cmd_prepare($o); break;
    case 'verify':   cmd_verify($o); break;
    case 'selftest': cmd_selftest(); break;
    default: fwrite(STDERR, "usage: php attest_verify.php prepare|verify|selftest [options] (see header)\n"); exit(2);
}
