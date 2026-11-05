<?php
// Read-only data: the SKID index of issued device certificates (SQLite, built by tools/build_index.php) and the PKI certificates.

function data_dir(): string { return rtrim(getenv('ATTEST_DATA') ?: dirname(__DIR__), '/\\'); }

function index_open(): ?PDO {
    $f = getenv('ATTEST_INDEX') ?: data_dir() . '/data/index.sqlite';
    if (!is_file($f) || !class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers(), true)) return null;
    try { return new PDO('sqlite:' . $f, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY]); }
    catch (Throwable $e) { return null; }
}

// 'known' | 'revoked' | 'unknown'; $skid: hex SHA-1 (40) or SHA-256 (64) of 04||x||y
function skid_lookup(string $skid): string {
    static $db = false;
    if ($db === false) $db = index_open();
    if ($db === null) return 'unknown';
    $q = $db->prepare('SELECT revoked FROM certs WHERE skid1 = ? OR skid256 = ? LIMIT 1');
    $q->execute([$skid, $skid]);
    $row = $q->fetch(PDO::FETCH_NUM);
    return $row === false ? 'unknown' : ($row[0] ? 'revoked' : 'known');
}

// level 2: the device key. A revoked certificate makes the token invalid; an unknown key leaves it valid_unverified.
// $cert: result of device_cert_check() when the device certificate was sent - it decides alone (valid / invalid), unless the PKI is not synced
function attest_status(array $r, ?array $cert = null): array {
    if (!$r['ok']) return ['status' => 'invalid'];
    if ($cert !== null && $cert['state'] !== 'unavailable') {
        return $cert['state'] === 'ok' ? ['status' => 'valid', 'expired' => $r['expired']] : ['status' => 'invalid'];
    }
    $k = skid_lookup($r['skid1']);
    if ($k === 'unknown') $k = skid_lookup($r['skid256']);
    if ($k === 'revoked') return ['status' => 'invalid'];
    return ['status' => $k === 'known' ? 'valid' : 'valid_unverified', 'expired' => $r['expired']];
}

// the Encedo CA certificates, for offline chain building in the SDK
function pki_list(): array {
    $out = [];
    foreach (glob(data_dir() . '/pki/*.pem') ?: [] as $f) {
        $pem = file_get_contents($f);
        $c = @openssl_x509_parse($pem);
        if (!$c) continue;
        $out[] = ['subject' => $c['name'], 'issuer' => openssl_x509_parse($pem, false)['issuer']['commonName'] ?? '',
                  'not_after' => $c['validTo_time_t'], 'sha256' => openssl_x509_fingerprint($pem, 'sha256'), 'pem' => $pem];
    }
    return $out;
}
