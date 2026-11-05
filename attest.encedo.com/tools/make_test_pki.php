<?php
/*
 * TEST ONLY: a throw-away Encedo-like PKI so the service can be tried without the real CA.
 *   php tools/make_test_pki.php [--jwt <token or file>] ...
 * Writes tools/testca/ (CA keys, never served), pki/test-root.pem, pki/test-intermediate.pem,
 * issued/test-device-<skid>.pem for 3 random device keys and for the jwk of every --jwt given (a certificate for that public key).
 */
require __DIR__ . '/../lib/verify.php';

$root = dirname(__DIR__);
$ca = __DIR__ . '/testca';
@mkdir($ca, 0777, true); @mkdir("$root/pki", 0777, true); @mkdir("$root/issued", 0777, true);

function run(array $args): void {
    $cmd = escapeshellarg(ossl_bin()); foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    exec($cmd . ' 2>&1', $o, $rc);
    if ($rc !== 0) { fwrite(STDERR, "openssl failed: $cmd\n" . implode("\n", $o) . "\n"); exit(1); }
}
$ext = "$ca/ext.cnf";
file_put_contents($ext, "[ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n[ica]\nbasicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n[dev]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n");

if (!is_file("$ca/root.key")) {
    run(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384', '-out', "$ca/root.key"]);
    run(['req', '-x509', '-new', '-key', "$ca/root.key", '-subj', '/C=UK/O=Encedo Ltd TEST/CN=Encedo TEST Root CA', '-days', '3650', '-sha384', '-config', $ext, '-extensions', 'ca', '-out', "$root/pki/test-root.pem"]);
    run(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', "$ca/int.key"]);
    run(['req', '-new', '-key', "$ca/int.key", '-subj', '/C=UK/O=Encedo Ltd TEST/CN=Encedo TEST Device CA', '-out', "$ca/int.csr"]);
    run(['x509', '-req', '-in', "$ca/int.csr", '-CA', "$root/pki/test-root.pem", '-CAkey', "$ca/root.key", '-days', '1825', '-sha384', '-extfile', $ext, '-extensions', 'ica', '-out', "$root/pki/test-intermediate.pem"]);
    echo "test CA created\n";
}

function issue(string $pubPem, string $cn): string {   // device certificate for a given public key (no CSR: -force_pubkey)
    global $ca, $root, $ext;
    $pub = "$ca/pub.pem"; file_put_contents($pub, $pubPem);
    $k = openssl_pkey_get_details(openssl_pkey_get_public($pubPem));
    $skid = sha1("\x04" . str_pad($k['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($k['ec']['y'], 32, "\0", STR_PAD_LEFT));
    $out = "$root/issued/test-device-$skid.pem";
    run(['x509', '-new', '-force_pubkey', $pub, '-subj', "/C=UK/O=Encedo Ltd TEST/CN=$cn", '-CA', "$root/pki/test-intermediate.pem", '-CAkey', "$ca/int.key", '-days', '3650', '-sha256', '-extfile', $ext, '-extensions', 'dev', '-out', $out]);
    return $skid;
}

$cnf = "$ca/php.cnf"; file_put_contents($cnf, "[req]\ndistinguished_name = dn\n[dn]\n");   // PHP on Windows has no default openssl.cnf
for ($i = 0; $i < 3; $i++) {
    $k =openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
    echo 'issued random device ', issue(openssl_pkey_get_details($k)['key'], '#TEST' . bin2hex(random_bytes(4))), "\n";
}
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] !== '--jwt') continue;
    $t = $argv[++$i] ?? ''; if (is_file($t)) $t = trim(file_get_contents($t));
    $hdr = json_decode((string)b64url_dec(explode('.', $t)[0] ?? ''), true);
    $x = b64url_dec($hdr['jwk']['x'] ?? ''); $y = b64url_dec($hdr['jwk']['y'] ?? '');
    if (!$x || !$y) { fwrite(STDERR, "--jwt: no jwk\n"); exit(1); }
    echo 'issued for the jwt device ', issue(spki_pem('SECP256R1', "\x04$x$y"), '#TEST-JWT'), "\n";
}
