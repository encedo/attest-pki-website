<?php
/*
 * Device certificate chain against the synced Encedo PKI (tools/sync_pki.php first), without device keys:
 * the certificate's own public key stands in for the jwk, so only the chain, the CRLs and the issuing CA are tested.
 *   php -d extension=pdo_sqlite tests/chain.php <cert.pem>=<state>[:<model>] ...
 *   e.g. tests/chain.php epa-01.pem=ok:EPA 0156.pem=ok:PPA foreign.pem=invalid
 * Every certificate expected "ok" is also checked against another key, which must give "invalid".
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';

if (!pki_ready()) { fwrite(STDERR, "Encedo PKI not synced (php tools/sync_pki.php)\n"); exit(2); }
if ($argc < 2) { fwrite(STDERR, "usage: tests/chain.php <cert.pem>=<state>[:<model>] ...\n"); exit(2); }

function own_point(string $pem): ?string {
    $k = @openssl_pkey_get_details(openssl_pkey_get_public($pem));
    if (!isset($k['ec']['x'])) return null;
    return "\x04" . str_pad($k['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($k['ec']['y'], 32, "\0", STR_PAD_LEFT);
}

$fail = 0;
foreach (array_slice($argv, 1) as $arg) {
    [$file, $want] = explode('=', $arg, 2) + [1 => ''];
    [$wstate, $wmodel] = explode(':', $want, 2) + [1 => ''];
    $pem = (string)file_get_contents($file);
    $r = device_cert_check($pem, own_point($pem));
    $model = $r['cert']['model'] ?? '';
    $ok = $r['state'] === $wstate && ($wmodel === '' || $model === $wmodel);
    printf("%s %-40s %-8s %-4s %s\n", $ok ? 'OK  ' : 'FAIL', basename($file), $r['state'], $model, $r['why']);
    if (!$ok) $fail++;
    if ($wstate === 'ok') {   // the same certificate for a token of another key
        $other = "\x04" . random_bytes(64);
        $r2 = device_cert_check($pem, $other);
        $ok2 = $r2['state'] === 'invalid';
        printf("%s %-40s %-8s      %s\n", $ok2 ? 'OK  ' : 'FAIL', basename($file) . ' (other key)', $r2['state'], $r2['why']);
        if (!$ok2) $fail++;
    }
}
echo $fail ? "$fail FAILED\n" : "ALL OK\n";
exit($fail ? 1 : 0);
