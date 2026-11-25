<?php
/*
 * Firmware releases against the Encedo Signer CA (the firmware branch of the Encedo Root CA, apart from the device branch).
 *
 *   fw_verify($cid)  a signed image by its IPFS CID: publisher signature, publisher certificate, ledger block, approvers
 *   fw_skid($id)     is a key a release key of Encedo: ['known' => bool, 'role' => 'User1' | 'User2' | 'Publisher']
 * With valid also: ledger (included | not_in_ledger | unavailable, lib/ledger.php) and user1_approval
 * (verified | invalid | not_recorded: User1's signature from the receipt, variant B).
 *
 * Trust:
 *   - the image is fetched from the IPFS gateway and its CID recomputed here (the gateway is not trusted);
 *   - its footer is signed by the publisher (Ed25519 over sha512(body || footer[0:192])) and names the ledger block (CID);
 *   - the block is fetched and its CID recomputed, so the block is the one the publisher signed;
 *   - the publisher key (footer) and the two approvers (block: user1_keyid, user2_keyid) must hold certificates of the
 *     Encedo Signer CA with the matching role (OU, EKU), chain to the pinned root and not be revoked.
 * Certificate dates do not limit a release (as for devices: -no_check_time); revocation does.
 *
 * Data (ATTEST_DATA): pki/{root-ca,signer-ca}.pem + crl/{root-ca,signer-ca}.crl.pem (tools/sync_pki.php),
 *   signer/*.pem the certificates of the release keys (copied from the CA, not in git, never served).
 * Gateway: ATTEST_IPFS_GATEWAY [https://ipfs.encedo.com/ipfs/]
 */

require_once __DIR__ . '/ledger.php';

const FW_CA = ['root-ca', 'signer-ca'];
const FW_ARC = '2.25.295977715113280988002148314551091508392';
const FW_POLICY = FW_ARC . '.1';
const FW_EKU = ['User1' => FW_ARC . '.2.1', 'User2' => FW_ARC . '.2.1', 'Publisher' => FW_ARC . '.2.2'];
const FW_ED25519_SPKI = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";
const FW_FOOTER = 'VVersion/VBootloaderAddress/VBootloaderLength/VApplicationAddress/VApplicationLength/a32ApplicationPublicKey/'
                . 'a48MyName/VApplicationVersionNumber/VTimeStamp/CSignMode/a36CID/a15Placeholder/a32Publisher/a64Signature';
const FW_VARIANT = [0xdeadcafe => 'ppa', 0xdeadbeef => 'epa'];
const FW_SIZES = [128 * 1024, 1024 * 1024];
const FW_MAX_BLOCK = 65536;

// true when the root and the Signer CA with their CRLs are synced and the root is the pinned one
// ($rootSha256: the pinned root; only tests pass another one, a request cannot)
function fw_ready(string $rootSha256 = ROOT_SHA256): bool {
    $d = data_dir();
    foreach (FW_CA as $n) if (!is_file("$d/pki/$n.pem") || !is_file("$d/crl/$n.crl.pem")) return false;
    $der = pem_to_der((string)file_get_contents("$d/pki/root-ca.pem"));
    return $der !== null && hash_equals($rootSha256, hash('sha256', $der));
}

function fw_signer_dir(): string { return getenv('ATTEST_SIGNER') ?: data_dir() . '/signer'; }

// a certificate of the Signer CA for this role: OU, EKU, policy, CA:FALSE, chain to the root through the Signer CA, CRLs
function fw_cert_ok(string $pem, string $role): bool {
    $c = @openssl_x509_parse($pem);
    if (!$c || !isset(FW_EKU[$role]) || ($c['subject']['OU'] ?? null) !== $role) return false;
    $e = $c['extensions'] ?? [];
    if (trim((string)($e['extendedKeyUsage'] ?? '')) !== FW_EKU[$role]) return false;
    if (!str_contains((string)($e['certificatePolicies'] ?? ''), FW_POLICY)) return false;
    if (!str_contains((string)($e['basicConstraints'] ?? ''), 'CA:FALSE')) return false;
    $d = data_dir();
    $tmp = tempnam(sys_get_temp_dir(), 'fw');
    file_put_contents($tmp, $pem);
    $crl = []; foreach (FW_CA as $n) { $crl[] = '-CRLfile'; $crl[] = "$d/crl/$n.crl.pem"; }
    [$rc] = ossl_run(array_merge(['verify', '-no_check_time', '-crl_check_all'], $crl, ['-CAfile', "$d/pki/root-ca.pem", '-untrusted', "$d/pki/signer-ca.pem", $tmp]));
    @unlink($tmp);
    return $rc === 0;
}

// the release key certificates in signer/: [{pem, role, cn, keyid (SHA-256 of the DER public key), ski (SHA-1 of the key)}]
function fw_certs(): array {
    static $all = null;
    if ($all !== null) return $all;
    $all = [];
    foreach (glob(fw_signer_dir() . '/*.pem') ?: [] as $f) {
        $pem = (string)file_get_contents($f);
        $c = @openssl_x509_parse($pem);
        $k = @openssl_pkey_get_public($pem);
        if (!$c || !$k) continue;
        $der = pem_to_der(openssl_pkey_get_details($k)['key']);
        if ($der === null) continue;
        $all[] = ['pem' => $pem, 'role' => (string)($c['subject']['OU'] ?? ''), 'cn' => (string)($c['subject']['CN'] ?? ''),
                  'keyid' => hash('sha256', $der), 'ski' => sha1(fw_spki_key($der))];
    }
    return $all;
}

// the subjectPublicKey bits of a DER SubjectPublicKeyInfo (what the SKID hashes)
function fw_spki_key(string $der): string {
    $p = 1; $l = ord($der[$p++]); if ($l & 0x80) $p += $l & 0x7f;            // outer SEQUENCE
    $p++; $l = ord($der[$p++]); if ($l & 0x80) { $n = $l & 0x7f; $l = 0; for ($i = 0; $i < $n; $i++) $l = $l * 256 + ord($der[$p++]); }
    $p += $l;                                                               // AlgorithmIdentifier
    $p++; $l = ord($der[$p++]); if ($l & 0x80) { $n = $l & 0x7f; $l = 0; for ($i = 0; $i < $n; $i++) $l = $l * 256 + ord($der[$p++]); }
    return substr($der, $p + 1, $l - 1);                                    // BIT STRING without the unused-bits byte
}

// a valid release key certificate by keyid (64 hex) or SKID (40 hex), optionally of one role
function fw_find(string $id, ?string $role = null): ?array {
    $id = strtolower($id);
    foreach (fw_certs() as $c) {
        if ($id !== $c['keyid'] && $id !== $c['ski']) continue;
        if ($role !== null && $c['role'] !== $role) continue;
        if (fw_cert_ok($c['pem'], $c['role'])) return $c;
    }
    return null;
}

function fw_skid(string $id, string $rootSha256 = ROOT_SHA256): array {
    $c = fw_ready($rootSha256) ? fw_find($id) : null;
    return $c === null ? ['known' => false] : ['known' => true, 'role' => $c['role']];
}

// ---------------------------------------------------------------- IPFS: fetch through the gateway, recompute the CID

function fw_gateway_get(string $cid, int $max): ?string {
    $url = rtrim(getenv('ATTEST_IPFS_GATEWAY') ?: 'https://ipfs.encedo.com/ipfs/', '/') . '/' . $cid;
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'ignore_errors' => false], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $d = @file_get_contents($url, false, $ctx, 0, $max + 1);
    return ($d === false || strlen($d) > $max) ? null : $d;
}

function fw_b58(string $bin): string {
    $A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $digits = [];
    foreach (str_split($bin) as $ch) {
        $carry = ord($ch);
        foreach ($digits as $i => $d) { $carry += $d << 8; $digits[$i] = $carry % 58; $carry = intdiv($carry, 58); }
        while ($carry) { $digits[] = $carry % 58; $carry = intdiv($carry, 58); }
    }
    $s = str_repeat('1', strspn($bin, "\0"));
    for ($i = count($digits) - 1; $i >= 0; $i--) $s .= $A[$digits[$i]];
    return $s;
}

function fw_varint(int $n): string { $o = ''; while ($n > 0x7f) { $o .= chr(($n & 0x7f) | 0x80); $n >>= 7; } return $o . chr($n); }
function fw_pb(int $field, string $bytes): string { return chr($field << 3 | 2) . fw_varint(strlen($bytes)) . $bytes; }

// CIDv0 of a file as `ipfs add` makes it (UnixFS, dag-pb, 256 KiB chunks, balanced, no raw leaves): Qm...
function fw_cidv0(string $data): string {
    $mh = fn(string $node) => "\x12\x20" . hash('sha256', $node, true);
    $leaf = fn(string $chunk) => fw_pb(1, "\x08\x02" . ($chunk === '' ? '' : fw_pb(2, $chunk)) . "\x18" . fw_varint(strlen($chunk)));
    $chunks = str_split($data, 262144) ?: [''];
    if (count($chunks) === 1) return fw_b58($mh($leaf($chunks[0])));
    if (count($chunks) > 174) throw new RuntimeException('file too large for one DAG level');
    $links = ''; $sizes = '';
    foreach ($chunks as $c) {
        $node = $leaf($c);
        $links .= fw_pb(2, fw_pb(1, $mh($node)) . fw_pb(2, '') . "\x18" . fw_varint(strlen($node)));
        $sizes .= "\x20" . fw_varint(strlen($c));
    }
    return fw_b58($mh($links . fw_pb(1, "\x08\x02\x18" . fw_varint(strlen($data)) . $sizes)));
}

// ---------------------------------------------------------------- the release

// 'valid' with what was checked | 'invalid' (no reason, like the device answers) | 'unavailable' (gateway / PKI not synced)
// ($get: cid, max bytes -> bytes | null, the gateway by default; $rootSha256: see fw_ready - both for tests only)
function fw_verify(string $cid, ?callable $get = null, string $rootSha256 = ROOT_SHA256, string $ipns = LEDGER_IPNS): array {
    if (!preg_match('/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/', $cid)) return ['status' => 'invalid'];
    if (!fw_ready($rootSha256)) return ['status' => 'unavailable'];
    $ledgerGet = $get ?? 'ledger_get';
    $get ??= 'fw_gateway_get';

    $img = $get($cid, max(FW_SIZES));
    if ($img === null) return ['status' => 'unavailable'];
    if (!in_array(strlen($img), FW_SIZES, true) || fw_cidv0($img) !== $cid) return ['status' => 'invalid'];
    $f = unpack(FW_FOOTER, substr($img, -256));
    if (!isset(FW_VARIANT[$f['Version']])) return ['status' => 'invalid'];
    $len = strlen($img) === 128 * 1024 ? $f['BootloaderLength'] : $f['ApplicationLength'];
    if ($f['BootloaderAddress'] !== 0x00400000 || $f['ApplicationAddress'] !== 0x00420000 || $len !== strlen($img)) return ['status' => 'invalid'];

    // publisher signature over the body and the footer up to the signature
    $msg = hash('sha512', substr($img, 0, -256) . substr($img, -256, 192), true);
    if (!sodium_crypto_sign_verify_detached($f['Signature'], $msg, $f['Publisher'])) return ['status' => 'invalid'];
    $pubKeyid = hash('sha256', FW_ED25519_SPKI . $f['Publisher']);
    $publisher = fw_find($pubKeyid, 'Publisher');
    if ($publisher === null) return ['status' => 'invalid'];

    // the ledger block named in the signed footer
    $blockCid = fw_b58(substr($f['CID'], 0, 34));
    $block = $get($blockCid, FW_MAX_BLOCK);
    if ($block === null) return ['status' => 'unavailable'];
    if (fw_cidv0($block) !== $blockCid) return ['status' => 'invalid'];
    $b = json_decode($block, true);
    $p = is_array($b) ? ($b['payload'] ?? null) : null;
    if (!is_array($p) || !is_int($b['blockSequence'] ?? null)) return ['status' => 'invalid'];
    if (($p['publisher_keyid'] ?? '') !== $pubKeyid) return ['status' => 'invalid'];
    $u1 = is_string($p['user1_keyid'] ?? null) ? fw_find($p['user1_keyid'], 'User1') : null;
    $u2 = is_string($p['user2_keyid'] ?? null) ? fw_find($p['user2_keyid'], 'User2') : null;
    if ($u1 === null || $u2 === null || $u1['keyid'] === $u2['keyid']) return ['status' => 'invalid'];

    // S5: is the block in the ledger history attest has witnessed, and did User1 approve this image (receipt v2)
    [$ledger, $st] = ledger_block_state($blockCid, $ledgerGet, $ipns);
    $approval = $ledger === 'included' ? ledger_approval($st, $cid, $img, $blockCid, $u1, $ledgerGet) : 'not_recorded';

    return ['status' => 'valid', 'ledger' => $ledger, 'user1_approval' => $approval,
            'name' => rtrim($f['MyName'], "\0 "), 'variant' => FW_VARIANT[$f['Version']],
            'filename' => (string)($p['metadata']['filename'] ?? ''), 'signed' => $f['TimeStamp'],
            'block' => $b['blockSequence'], 'block_cid' => $blockCid,
            'user1' => $u1['cn'], 'user2' => $u2['cn'], 'publisher' => $publisher['cn']];
}
