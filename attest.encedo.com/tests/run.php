<?php
/*
 * Tests of the validation logic (no web server needed).
 *   php -d extension=pdo_sqlite tests/run.php [real-jwt-file [real-crt-file]]
 * Builds its own throw-away index in a temp dir (one known and one revoked device key), signs test tokens like the firmware does
 * and checks the status of each. With a file holding a real device JWT it also checks that one (expected: signature valid).
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';

$tmp = sys_get_temp_dir() . '/attest_test_' . getmypid();
@mkdir("$tmp/issued", 0777, true);

$CNF = "$tmp/openssl.cnf"; file_put_contents($CNF, "[req]\ndistinguished_name = dn\n[dn]\n");   // PHP on Windows has no default openssl.cnf
function ec_key(string $curve) { global $CNF; return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve, 'config' => $CNF]); }
function point($k): string { $d = openssl_pkey_get_details($k)['ec']; $n = strlen($d['x']) > 32 ? strlen($d['x']) : 32; return "\x04" . str_pad($d['x'], $n, "\0", STR_PAD_LEFT) . str_pad($d['y'], $n, "\0", STR_PAD_LEFT); }
function compressed($k, int $size): string { $d = openssl_pkey_get_details($k)['ec']; $y = str_pad($d['y'], $size, "\0", STR_PAD_LEFT); return chr(2 | (ord($y[$size - 1]) & 1)) . str_pad($d['x'], $size, "\0", STR_PAD_LEFT); }
function der2rs(string $der, int $size): string {
    $p = 2; if (ord($der[1]) & 0x80) $p += ord($der[1]) & 0x7f; $out = '';
    for ($k = 0; $k < 2; $k++) { $l = ord($der[$p + 1]); $v = ltrim(substr($der, $p + 2, $l), "\0"); $out .= str_pad($v, $size, "\0", STR_PAD_LEFT); $p += 2 + $l; }
    return $out;
}
function self_cert($k, string $file): void {   // the index reads only the public key of the certificate
    global $CNF;
    $csr = openssl_csr_new(['commonName' => 'test device'], $k, ['digest_alg' => 'sha256', 'config' => $CNF]);
    openssl_x509_export(openssl_csr_sign($csr, null, $k, 365, ['digest_alg' => 'sha256', 'config' => $CNF]), $pem);
    file_put_contents($file, $pem);
}
function ossl_cli(array $args): void { $cmd = escapeshellarg(ossl_bin()); foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a); exec($cmd . ' 2>&1', $o, $rc); if ($rc) { echo implode("\n", $o), "\n"; exit(1); } }
function cli_key(string $alg): array {   // Ed448 / ML-DSA via openssl CLI: [private PEM file, raw public key]
    global $tmp; $f = "$tmp/" . $alg . '.key'; ossl_cli(['genpkey', '-algorithm', $alg, '-out', $f]);
    ossl_cli(['pkey', '-in', $f, '-pubout', '-outform', 'DER', '-out', "$f.pub"]);
    $der = file_get_contents("$f.pub"); $len = ['ED448' => 57, 'ML-DSA-44' => 1312][$alg];
    return [$f, substr($der, -$len)];
}
function cli_sign(string $keyFile, string $msg): string { global $tmp; file_put_contents("$tmp/m", $msg); ossl_cli(['pkeyutl', '-sign', '-inkey', $keyFile, '-rawin', '-in', "$tmp/m", '-out', "$tmp/s"]); return file_get_contents("$tmp/s"); }

// a token as the firmware makes it; $pop: null | callable(aud, nonce) -> [key claim, pop]
function token($dev, array $o = []): string {
    $pt = point($dev);
    $hdr = ['alg' => 'ES256', 'typ' => 'encedo-attest+jwt', 'kid' => $o['kid'] ?? sha1($pt), 'jwk' => ['kty' => 'EC', 'crv' => 'P-256', 'x' => b64url_enc(substr($pt, 1, 32)), 'y' => b64url_enc(substr($pt, 33, 32))]];
    $now = time() + ($o['shift'] ?? 0); $aud = 'test-verifier'; $nonce = random_bytes(32);
    $body = ['iss' => 'https://attest.encedo.com', 'aud' => $aud, 'iat' => $now, 'exp' => $now + 300, 'nonce' => base64_encode($nonce),
             'jti' => '67f3d46c-6912-4692-9979-621d2998b8d8', 'device' => ['hwv' => 'PPA rev 2.2', 'fwv' => 'Encedo nGINE FW v1.3.0', 'blv' => 'Encedo Secure Bootloader v2.0.2', 'cc_mode' => 0, 'policy' => []]];
    if (isset($o['pop'])) [$body['key'], $body['pop']] = ($o['pop'])($aud, $nonce);
    if (isset($o['body'])) $body = array_merge($body, $o['body']);
    $si = b64url_enc(json_encode($hdr, JSON_UNESCAPED_SLASHES)) . '.' . b64url_enc(json_encode($body, JSON_UNESCAPED_SLASHES));
    openssl_sign($si, $der, $dev, OPENSSL_ALGO_SHA256);
    return $si . '.' . b64url_enc(der2rs($der, 32));
}
function key_claim(string $type, string $pub, array $modes): array { return ['kid' => bin2hex(random_bytes(16)), 'type' => $type, 'modes' => $modes, 'pubkey' => ['primary' => base64_encode($pub)], 'properties' => ['privatekey' => true, 'derived' => false]]; }
function canon(string $aud, string $nonce, string $pub): string { return cn(PFX_SIG) . cn($aud) . cn($pub) . cn($nonce); }

// ---- data: one known device, one revoked device
$known = ec_key('prime256v1'); $revoked = ec_key('prime256v1'); $unknown = ec_key('prime256v1');
self_cert($known, "$tmp/issued/known.pem"); self_cert($revoked, "$tmp/issued/revoked.pem");
file_put_contents("$tmp/revoked.txt", "# test\n" . sha1(point($revoked)) . "\n");
passthru('php -d extension=pdo_sqlite ' . escapeshellarg(__DIR__ . '/../tools/build_index.php') . ' ' . escapeshellarg("$tmp/issued") . ' ' . escapeshellarg("$tmp/revoked.txt") . ' ' . escapeshellarg("$tmp/index.sqlite"));
putenv("ATTEST_INDEX=$tmp/index.sqlite");

$fail = 0;
function expect(string $name, string $jwt, string $status, ?bool $expired = null, ?string $pop = null, ?string $crt = null): void {
    global $fail;
    $r = attest_check($jwt); $c = ($crt !== null && $r['ok']) ? device_cert_check($crt, $r['point']) : null; $s = attest_status($r, $c);
    if ($c && $c['why'] !== '') $r['why'] = $c['why'];
    $ok = $s['status'] === $status && ($expired === null || ($s['expired'] ?? null) === $expired) && ($pop === null || $r['pop'][1] === $pop);
    printf("%-52s %-17s %s%s\n", $name, $s['status'] . (!empty($s['expired']) ? '+expired' : ''), $ok ? 'OK' : 'FAIL', $ok || $r['why'] === '' ? '' : " ({$r['why']})");
    if (!$ok) $fail++;
}

// ---- level 1 + 2
expect('known device, fresh', token($known), 'valid', false);
expect('known device, expired', token($known, ['shift' => -3600]), 'valid', true);
expect('unknown device', token($unknown), 'valid_unverified', false);
expect('revoked device', token($revoked), 'invalid');
expect('header kid = SHA-256 of the key (FW 1.4)', token($known, ['kid' => hash('sha256', point($known))]), 'valid');
expect('header kid of another key', token($known, ['kid' => sha1(point($unknown))]), 'invalid');
$t = explode('.', token($known)); $b = json_decode(b64url_dec($t[1]), true); $b['aud'] = 'other';
expect('body changed after signing', $t[0] . '.' . b64url_enc(json_encode($b)) . '.' . $t[2], 'invalid');
$h = json_decode(b64url_dec($t[0]), true); $h['alg'] = 'none';
expect('alg none, no signature', b64url_enc(json_encode($h)) . '.' . $t[1] . '.', 'invalid');
expect('signature of another key', $t[0] . '.' . $t[1] . '.' . explode('.', token($unknown))[2], 'invalid');
expect('wrong iss', token($known, ['body' => ['iss' => 'https://evil.example']]), 'invalid');
expect('nonce 16 B', token($known, ['body' => ['nonce' => base64_encode(random_bytes(16))]]), 'invalid');
expect('truncated', substr(token($known), 0, 100), 'invalid');
expect('not a JWT', 'hello', 'invalid');
expect('whole {"attestation": ...} reply', json_encode(['attestation' => token($known)]), 'valid');

// ---- PoP signatures
foreach (['SECP256R1' => ['prime256v1', 32], 'SECP384R1' => ['secp384r1', 48], 'SECP521R1' => ['secp521r1', 66], 'SECP256K1' => ['secp256k1', 32]] as $type => [$curve, $size]) {
    $k = ec_key($curve); $pub = compressed($k, $size);
    $mk = fn($aud, $nonce) => [key_claim($type, $pub, ['ExDSA']), ['signature' => base64_encode((function () use ($k, $aud, $nonce, $pub, $type, $size) { openssl_sign(canon($aud, $nonce, $pub), $d, $k, NIST[$type]['algo']); return der2rs($d, $size); })())]];
    expect("PoP signature $type", token($known, ['pop' => $mk]), 'valid', false, 'ok');
}
$kp = sodium_crypto_sign_keypair(); $pub = sodium_crypto_sign_publickey($kp);
expect('PoP signature ED25519', token($known, ['pop' => fn($aud, $nonce) => [key_claim('ED25519', $pub, ['ExDSA']), ['signature' => base64_encode(sodium_crypto_sign_detached(canon($aud, $nonce, $pub), sodium_crypto_sign_secretkey($kp)))]]]), 'valid', false, 'ok');
expect('PoP signature ED25519, signed for another aud', token($known, ['pop' => fn($aud, $nonce) => [key_claim('ED25519', $pub, ['ExDSA']), ['signature' => base64_encode(sodium_crypto_sign_detached(canon('x', $nonce, $pub), sodium_crypto_sign_secretkey($kp)))]]]), 'invalid');
foreach (['ED448' => 'ED448', 'MLDSA44' => 'ML-DSA-44'] as $type => $alg) {
    [$kf, $pub] = cli_key($alg);
    expect("PoP signature $type", token($known, ['pop' => fn($aud, $nonce) => [key_claim($type, $pub, [$type === 'ED448' ? 'ExDSA' : 'MLDSA']), ['signature' => base64_encode(cli_sign($kf, canon($aud, $nonce, $pub)))]]]), 'valid', false, 'ok');
}
expect('PoP MAC (ECDH / KEM): not checked online', token($known, ['pop' => fn($aud, $nonce) => [key_claim('CURVE25519', random_bytes(32), ['ECDH']), ['mac' => base64_encode(random_bytes(32))]]]), 'valid', false, 'not checked');
expect('pop without key', token($known, ['body' => ['pop' => ['signature' => 'AAAA']]]), 'invalid');

// ---- device certificate against the Encedo PKI (needs tools/sync_pki.php; the real certificate as argument 2)
if (pki_ready()) {
    self_cert($known, "$tmp/self.pem");
    expect('crt: self-signed, key of the token', token($known), 'invalid', null, null, file_get_contents("$tmp/self.pem"));
    expect('crt: not a certificate', token($unknown), 'invalid', null, null, base64_encode(random_bytes(300)));
    if (isset($argv[2]) && is_file($argv[2])) {
        $real = file_get_contents($argv[2]);
        expect('crt: real Encedo certificate, token of another key', token($unknown), 'invalid', null, null, $real);
        preg_match('/eyJ[A-Za-z0-9_.-]+/', file_get_contents($argv[1]), $mm);
        expect('crt: real certificate + real token (chain, CRLs, key)', $mm[0] ?? '', 'valid', null, null, $real);
    }
} else echo "Encedo PKI not synced (php tools/sync_pki.php) - certificate cases skipped\n";

// ---- a real device token
if (isset($argv[1]) && is_file($argv[1])) {
    preg_match('/eyJ[A-Za-z0-9_.-]+/', file_get_contents($argv[1]), $mm);   // the JWT inside any text (JSON line, md)
    $r = attest_check($mm[0] ?? ''); $s = attest_status($r);
    printf("%-52s %-17s %s\n", 'real device JWT (' . basename($argv[1]) . ')', $s['status'] . (!empty($s['expired']) ? '+expired' : ''), $r['ok'] ? 'signature OK, pop ' . $r['pop'][0] . ' ' . $r['pop'][1] : "FAIL ({$r['why']})");
    if (!$r['ok']) $fail++;
}

foreach (array_merge(glob("$tmp/issued/*") ?: [], glob("$tmp/*") ?: []) as $f) if (is_file($f)) @unlink($f);   // the index stays open (Windows: left in temp)
@rmdir("$tmp/issued"); @rmdir($tmp);
echo $fail ? "\n$fail FAILED\n" : "\nALL OK\n";
exit($fail ? 1 : 0);
