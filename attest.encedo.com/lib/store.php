<?php
// Read-only data: the SKID index of issued device certificates (SQLite, built by tools/build_index.php) and the PKI certificates.

function data_dir(): string { return rtrim(getenv('ATTEST_DATA') ?: dirname(__DIR__), '/\\'); }

function index_open(): ?PDO {
    $f = getenv('ATTEST_INDEX') ?: data_dir() . '/data/index.sqlite';
    if (!is_file($f) || !class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers(), true)) return null;
    try { return new PDO('sqlite:' . $f, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY]); }
    catch (Throwable $e) { return null; }
}

function index_db(): ?PDO {   // DEV-509: one read-only connection per request (was static in skid_lookup)
    static $db = false;
    if ($db === false) $db = index_open();
    return $db;
}

// the index row of an issued certificate (revoked, model, file) or null; $skid: hex SHA-1 (40) or SHA-256 (64) of 04||x||y
function index_row(string $skid): ?array {
    $db = index_db();
    if ($db === null || $skid === '') return null;
    $q = $db->prepare('SELECT revoked, model, file FROM certs WHERE skid1 = ? OR skid256 = ? LIMIT 1');
    $q->execute([$skid, $skid]);
    $row = $q->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row;
}

// 'known' | 'revoked' | 'unknown'
function skid_lookup(string $skid): string {
    $row = index_row($skid);
    return $row === null ? 'unknown' : ($row['revoked'] ? 'revoked' : 'known');
}

// DEV-509: a SKID listed in revoked.txt - also the SKIDs of EPA HEM certificates, which are not in issued/
function skid_revoked(string $skid): bool {
    $db = index_db();
    if ($db === null || $skid === '') return false;
    $q = $db->prepare('SELECT 1 FROM revoked WHERE skid = ? LIMIT 1');
    $q->execute([strtolower($skid)]);
    return $q->fetch() !== false;
}

// DEV-509: the board certificate (PEM) of an EPA HEM certificate - the issued certificate whose key SHA-1 is $skid1 (the AKID of the
// HEM certificate); null if unknown or revoked. issued/ next to the index data (ATTEST_ISSUED overrides it, tests)
function board_find(string $skid1): ?string {
    $row = index_row($skid1);
    if ($row === null || $row['revoked'] || !preg_match('/^[\w.-]+\.pem$/', (string)$row['file'])) return null;
    $pem = @file_get_contents((getenv('ATTEST_ISSUED') ?: data_dir() . '/issued') . '/' . $row['file']);
    return ($pem !== false && @openssl_x509_read($pem)) ? $pem : null;
}

// level 2: the device key. A revoked certificate makes the token invalid; an unknown key leaves it valid_unverified.
// $cert: result of device_cert_check() when the device certificate was sent - it decides alone (valid / invalid), unless the PKI is not synced
// DEV-509: "assurance" with valid - "hard" (PPA, secure element per chip) / "soft" (EPA) from the certificate path or the index, never
// from the token claim
function attest_status(array $r, ?array $cert = null): array {
    if (!$r['ok']) return ['status' => 'invalid'];
    if ($cert !== null && $cert['state'] !== 'unavailable') {
        return $cert['state'] === 'ok' ? ['status' => 'valid', 'expired' => $r['expired'], 'assurance' => $cert['assurance']] : ['status' => 'invalid'];
    }
    $row = index_row($r['skid1']) ?? index_row($r['skid256']);
    if ($row !== null && $row['revoked']) return ['status' => 'invalid'];
    if ($row === null) return ['status' => 'valid_unverified', 'expired' => $r['expired']];
    $out = ['status' => 'valid', 'expired' => $r['expired']];
    if (isset(PKI_ASSURANCE[$row['model']])) $out['assurance'] = PKI_ASSURANCE[$row['model']];   // none for a certificate of no Encedo issuing CA
    return $out;
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
