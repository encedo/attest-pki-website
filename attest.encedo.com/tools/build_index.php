<?php
/*
 * Build the read-only SKID index from the issued device certificates.
 *   php -d extension=pdo_sqlite tools/build_index.php [issued_dir] [revoked.txt] [out.sqlite]
 * Defaults: issued/, revoked.txt, data/index.sqlite (next to this repo). The index is written to a temp file and renamed (atomic).
 * SKID = hash of 04||x||y of the certificate public key (SHA-1 and SHA-256), not the subjectKeyIdentifier extension set by the CA.
 * revoked.txt: one SKID (hex, SHA-1 or SHA-256) per line, '#' comments.
 */
$root = dirname(__DIR__);
$issued = $argv[1] ?? "$root/issued";
$revf = $argv[2] ?? "$root/revoked.txt";
$out = $argv[3] ?? "$root/data/index.sqlite";

$revoked = [];
if (is_file($revf)) foreach (file($revf, FILE_IGNORE_NEW_LINES) as $l) { $l = strtolower(trim(preg_replace('/#.*/', '', $l))); if ($l !== '') $revoked[$l] = true; }

@mkdir(dirname($out), 0777, true);
$tmp = $out . '.tmp'; @unlink($tmp);
$db = new PDO('sqlite:' . $tmp, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec('CREATE TABLE certs (skid1 TEXT NOT NULL, skid256 TEXT NOT NULL, serial TEXT, subject TEXT, not_before INTEGER, not_after INTEGER, revoked INTEGER NOT NULL, file TEXT)');
$ins = $db->prepare('INSERT INTO certs VALUES (?, ?, ?, ?, ?, ?, ?, ?)');

$n = 0; $skipped = 0; $nrev = 0;
$db->beginTransaction();
foreach (glob("$issued/*.pem") ?: [] as $f) {
    $pem = file_get_contents($f);
    $c = @openssl_x509_parse($pem); $k = @openssl_pkey_get_public($pem);
    $d = $k ? openssl_pkey_get_details($k) : null;
    if (!$c || !isset($d['ec']['x'], $d['ec']['y']) || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') { $skipped++; fwrite(STDERR, "skip (not a P-256 certificate): $f\n"); continue; }
    $point = "\x04" . str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT);
    $s1 = sha1($point); $s256 = hash('sha256', $point);
    $rev = isset($revoked[$s1]) || isset($revoked[$s256]);
    $ins->execute([$s1, $s256, $c['serialNumberHex'] ?? '', $c['name'] ?? '', $c['validFrom_time_t'], $c['validTo_time_t'], $rev ? 1 : 0, basename($f)]);
    $n++; $nrev += $rev ? 1 : 0;
}
$db->commit();
$db->exec('CREATE INDEX i1 ON certs (skid1)'); $db->exec('CREATE INDEX i256 ON certs (skid256)');
$ins = null; $db = null;   // close the file before the rename (Windows keeps it locked)
if (is_file($out)) @unlink($out);   // rename does not replace an open file on Windows; on Linux rename alone is atomic
if (!rename($tmp, $out)) { fwrite(STDERR, "cannot replace $out\n"); exit(1); }
echo "index: $n certificates ($nrev revoked, $skipped skipped) -> $out\n";
