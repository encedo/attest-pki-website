<?php
/*
 * Fetches the Encedo PKI from https://pki.encedo.com into the data dir (ATTEST_DATA, default: the project root):
 *   pki/<ca>.pem      CA certificates (published by /v1/pki, used for the chain)
 *   crl/<ca>.crl.pem  CRLs (PEM, for openssl verify -crl_check_all)
 *   <ca> = root-ca, attestation-ca, custody-ca (HEM PPA), epa-custody-ca (HEM EPA): PKI_CA in lib/pki.php
 *   php tools/sync_pki.php [base URL]
 * Every file is checked against SHA256SUMS, the root against the pinned fingerprint (ROOT_SHA256 in lib/pki.php), and the whole set with
 * openssl verify before anything is replaced. Run it from cron (the CRLs are reissued yearly; nextUpdate is shown on the page).
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';

$base = rtrim($argv[1] ?? 'https://pki.encedo.com', '/') . '/';
function fail(string $m): never { fwrite(STDERR, "sync_pki: $m\n"); exit(1); }
function fetch(string $url): string {
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'ignore_errors' => false], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $d = @file_get_contents($url, false, $ctx);
    if ($d === false || $d === '') fail("download $url");
    return $d;
}

$sums = [];
foreach (explode("\n", fetch($base . 'SHA256SUMS')) as $l) if (preg_match('/^([0-9a-f]{64})\s+\*?(\S+)$/', trim($l), $m)) $sums[$m[2]] = $m[1];
$get = function (string $name) use ($base, $sums): string {
    if (!isset($sums[$name])) fail("$name not in SHA256SUMS");
    $d = fetch($base . $name);
    if (!hash_equals($sums[$name], hash('sha256', $d))) fail("$name: SHA-256 differs from SHA256SUMS");
    return $d;
};

$tmp = sys_get_temp_dir() . '/attest_pki_' . getmypid();
@mkdir("$tmp/pki", 0777, true); @mkdir("$tmp/crl", 0777, true);
foreach (PKI_CA as $name) {
    $pem = $get("$name.pem");
    $der = $get("$name.cer");
    if (pem_to_der($pem) !== $der) fail("$name: PEM and DER differ");
    if ($name === 'root-ca' && !hash_equals(ROOT_SHA256, hash('sha256', $der))) fail('root-ca: not the pinned Encedo Root CA');
    file_put_contents("$tmp/pki/$name.pem", $pem);
    $crl = $get("$name.crl");
    if (!str_starts_with($crl, '-----BEGIN X509 CRL-----')) $crl = pem($crl, 'X509 CRL');
    file_put_contents("$tmp/crl/$name.crl.pem", $crl);
}

// both issuing CAs up to the pinned root through the Attestation CA, with all CRLs (a revoked intermediate fails here)
$issuing = array_map(fn($n) => "$tmp/pki/$n.pem", array_keys(PKI_ISSUING));
[$rc, $out] = ossl_run(array_merge(['verify', '-crl_check_all'], crl_args("$tmp/crl"), ['-CAfile', "$tmp/pki/root-ca.pem", '-untrusted', "$tmp/pki/attestation-ca.pem"], $issuing));
if ($rc !== 0) fail("chain check: $out");

$dst = data_dir();
foreach (['pki', 'crl'] as $d) {
    @mkdir("$dst/$d", 0755, true);
    foreach (glob("$tmp/$d/*") as $f) { rename($f, "$dst/$d/" . basename($f) . '.new'); rename("$dst/$d/" . basename($f) . '.new', "$dst/$d/" . basename($f)); }
    @rmdir("$tmp/$d");
}
@rmdir($tmp);
foreach (crl_info() as $c) echo "{$c['issuer']}: CRL next update ", gmdate('Y-m-d', $c['next']), ", ", $c['revoked'], " revoked\n";
echo "PKI synced from $base\n";
