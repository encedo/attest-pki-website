<?php
/*
 * Tests of the firmware release check (lib/firmware.php), no web server and no network.
 *   php tests/firmware.php
 * Makes a throw-away PKI in a temp dir while it runs (a test root, a test Signer CA, User1 / User2 / Publisher
 * certificates, one revoked User1, CRLs), signs test releases like cloud_signer does (ledger block -> footer CID ->
 * Ed25519 publisher signature) and serves them from an in-memory "gateway" that can also lie.
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';
require __DIR__ . '/../lib/firmware.php';

$tmp = sys_get_temp_dir() . '/attest_fw_' . getmypid();
foreach (['pki', 'crl', 'signer', 'ca/root', 'ca/signer', 'other'] as $d) @mkdir("$tmp/$d", 0777, true);
putenv("ATTEST_DATA=$tmp");
register_shutdown_function(fn () => exec('rm -rf ' . escapeshellarg($tmp)));

function ossl(array $args): void {
    $cmd = escapeshellarg(ossl_bin()); foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    exec($cmd . ' 2>&1', $o, $rc);
    if ($rc) { echo "openssl failed: $cmd\n", implode("\n", $o), "\n"; exit(1); }
}
$fail = 0;
function check(string $what, bool $ok): void { global $fail; echo ($ok ? 'OK   ' : 'FAIL ') . $what . "\n"; if (!$ok) $fail++; }

// ---- the test PKI: root -> Signer CA -> release keys, with openssl ca databases for the CRLs
$cnf = "$tmp/ca.cnf";
foreach (['root', 'signer'] as $ca) { touch("$tmp/ca/$ca/index.txt"); file_put_contents("$tmp/ca/$ca/serial", "01\n"); file_put_contents("$tmp/ca/$ca/crlnumber", "01\n"); }
file_put_contents($cnf, <<<CNF
[ca]
default_ca = root
[root]
dir = $tmp/ca/root
[signer]
dir = $tmp/ca/signer
[root_common]
[req]
distinguished_name = dn
[dn]
[v3_root]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_signer]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
certificatePolicies = 2.25.295977715113280988002148314551091508392.1
[v3_operator]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,2.25.295977715113280988002148314551091508392.2.1
certificatePolicies = 2.25.295977715113280988002148314551091508392.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[v3_publisher]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,2.25.295977715113280988002148314551091508392.2.2
certificatePolicies = 2.25.295977715113280988002148314551091508392.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF);
// openssl ca needs the database keys in each section
$c = file_get_contents($cnf);
foreach (['root', 'signer'] as $ca) {
    $c = str_replace("[$ca]\ndir = $tmp/ca/$ca\n", "[$ca]\ndir = $tmp/ca/$ca\ndatabase = \$dir/index.txt\nserial = \$dir/serial\ncrlnumber = \$dir/crlnumber\n"
        . "new_certs_dir = \$dir\ncertificate = $tmp/pki/$ca-ca.pem\nprivate_key = $tmp/ca/$ca/key.pem\ndefault_md = sha256\ndefault_crl_days = 30\n"
        . "policy = pol\nunique_subject = no\n", $c);
}
file_put_contents($cnf, $c . "\n[pol]\norganizationalUnitName = optional\ncommonName = supplied\n");

ossl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', "$tmp/ca/root/key.pem"]);
ossl(['req', '-x509', '-new', '-key', "$tmp/ca/root/key.pem", '-subj', '/CN=TEST Root', '-days', '30', '-config', $cnf, '-extensions', 'v3_root', '-out', "$tmp/pki/root-ca.pem"]);
ossl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', "$tmp/ca/signer/key.pem"]);
ossl(['req', '-new', '-key', "$tmp/ca/signer/key.pem", '-subj', '/CN=TEST Signer CA', '-config', $cnf, '-out', "$tmp/ca/signer/req.pem"]);
ossl(['x509', '-req', '-in', "$tmp/ca/signer/req.pem", '-CA', "$tmp/pki/root-ca.pem", '-CAkey', "$tmp/ca/root/key.pem", '-set_serial', '3', '-days', '30', '-extfile', $cnf, '-extensions', 'v3_signer', '-out', "$tmp/pki/signer-ca.pem"]);
$rootSha = hash('sha256', pem_to_der(file_get_contents("$tmp/pki/root-ca.pem")));

// a release key: [keyid, ski, private key]; P-256 for operators, Ed25519 (sodium secret key) for the publisher
function release_key(string $name, string $ou, string $ext, bool $ed25519 = false, string $dir = 'signer'): array {
    global $tmp, $cnf;
    if ($ed25519) {
        $kp = sodium_crypto_sign_keypair(); $pub = sodium_crypto_sign_publickey($kp); $sk = sodium_crypto_sign_secretkey($kp);
        file_put_contents("$tmp/$name.pub", pem(FW_ED25519_SPKI . $pub, 'PUBLIC KEY'));
        ossl(['x509', '-new', '-force_pubkey', "$tmp/$name.pub", '-subj', "/OU=$ou/CN=$name", '-CA', "$tmp/pki/signer-ca.pem", '-CAkey', "$tmp/ca/signer/key.pem",
              '-days', '30', '-extfile', $cnf, '-extensions', $ext, '-out', "$tmp/$dir/$name.pem"]);
        $der = FW_ED25519_SPKI . $pub;
    } else {
        ossl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', "$tmp/$name.key"]);
        ossl(['req', '-new', '-key', "$tmp/$name.key", '-subj', "/OU=$ou/CN=$name", '-config', $cnf, '-out', "$tmp/$name.csr"]);
        ossl(['ca', '-batch', '-config', $cnf, '-name', 'signer', '-days', '30', '-extensions', $ext, '-in', "$tmp/$name.csr", '-out', "$tmp/$dir/$name.pem", '-notext']);
        $der = pem_to_der(openssl_pkey_get_details(openssl_pkey_get_public(file_get_contents("$tmp/$dir/$name.pem")))['key']);
        $sk = null;
    }
    return ['keyid' => hash('sha256', $der), 'ski' => sha1(fw_spki_key($der)), 'sk' => $sk, 'pem' => "$tmp/$dir/$name.pem"];
}
$u1 = release_key('Alice', 'User1', 'v3_operator');
$u2 = release_key('Bob', 'User2', 'v3_operator');
$pub = release_key('Publisher', 'Publisher', 'v3_publisher', true);
$gone = release_key('Mallory', 'User1', 'v3_operator');
$wrongEku = release_key('Eve', 'User2', 'v3_publisher');                // OU User2, publisher EKU
$uncert = ['keyid' => '', 'sk' => sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair())];   // a publisher key with no certificate
$uncert['keyid'] = hash('sha256', FW_ED25519_SPKI . sodium_crypto_sign_publickey_from_secretkey($uncert['sk']));
ossl(['ca', '-config', $cnf, '-name', 'signer', '-revoke', $gone['pem'], '-crl_reason', 'keyCompromise']);
ossl(['ca', '-config', $cnf, '-name', 'signer', '-gencrl', '-out', "$tmp/crl/signer-ca.crl.pem"]);
ossl(['ca', '-config', $cnf, '-name', 'root', '-gencrl', '-out', "$tmp/crl/root-ca.crl.pem"]);

// ---- a release as cloud_signer makes it: block -> footer CID -> publisher signature over the image
$store = [];
$get = function (string $cid, int $max) use (&$store): ?string { return isset($store[$cid]) && strlen($store[$cid]) <= $max ? $store[$cid] : null; };
function release(array $user1, array $user2, array $publisher, ?array $signWith = null): string {
    global $store;
    $pk = sodium_crypto_sign_publickey_from_secretkey($publisher['sk']);
    $block = json_encode(['blockVersion' => 1, 'blockSequence' => 7, 'prevBlockCID' => 'QmTEST',
        'payload' => ['user1_keyid' => $user1['keyid'], 'user2_keyid' => $user2['keyid'], 'publisher_keyid' => $publisher['keyid'],
                      'staging_file_cid' => 'QmTEST', 'metadata' => ['filename' => 'encedo_bootloader_v.9.9.9_ppa.bin', 'filesize' => '131072']]], JSON_UNESCAPED_SLASHES);
    $blockCid = fw_cidv0($block); $store[$blockCid] = $block;
    $mh = "\x12\x20" . hash('sha256', fw_pb(1, "\x08\x02" . fw_pb(2, $block) . "\x18" . fw_varint(strlen($block))), true);   // the multihash in the footer
    if (fw_b58($mh) !== $blockCid) { echo "test: block multihash\n"; exit(1); }
    $footer = pack('VVVVVa32a48VVCa36a15a32', 0xdeadcafe, 0x00400000, 128 * 1024, 0x00420000, 1024 * 1024, random_bytes(32),
                   'Encedo Secure Bootloader vTEST', 0x09090900, time(), 0x80, $mh, '', $pk);
    $body = random_bytes(128 * 1024 - 256);
    $sig = sodium_crypto_sign_detached(hash('sha512', $body . $footer, true), ($signWith ?? $publisher)['sk']);
    $img = $body . $footer . $sig;
    $cid = fw_cidv0($img); $store[$cid] = $img;
    return $cid;
}

// ---- CID computation against known IPFS CIDs
check('CIDv0 of an empty file', fw_cidv0('') === 'QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH');
check('CIDv0 of "hello world\n"', fw_cidv0("hello world\n") === 'QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o');

// ---- releases
$ok = release($u1, $u2, $pub);
$r = fw_verify($ok, $get, $rootSha);
check('a release approved by User1 + User2, signed by the publisher: valid', $r['status'] === 'valid' && $r['user1'] === 'Alice' && $r['user2'] === 'Bob'
      && $r['publisher'] === 'Publisher' && $r['block'] === 7 && $r['variant'] === 'ppa' && $r['filename'] === 'encedo_bootloader_v.9.9.9_ppa.bin');
check('the same with the real root pinned (test PKI): unavailable', fw_verify($ok, $get)['status'] === 'unavailable');
check('not a CIDv0: invalid', fw_verify('bafyNOT', $get, $rootSha)['status'] === 'invalid');
check('not on the gateway: unavailable', fw_verify('Qm' . str_repeat('1', 44), $get, $rootSha)['status'] === 'unavailable');

$img = $store[$ok]; $img[1000] = chr(ord($img[1000]) ^ 1);
$store[$ok] = $img;
check('the gateway returns other bytes for the CID: invalid', fw_verify($ok, $get, $rootSha)['status'] === 'invalid');
$bad = fw_cidv0($img); $store[$bad] = $img;
check('an image changed after signing (fetched by its own CID): invalid', fw_verify($bad, $get, $rootSha)['status'] === 'invalid');

$ok2 = release($u1, $u2, $pub);
$f = unpack(FW_FOOTER, substr($store[$ok2], -256)); $bcid = fw_b58(substr($f['CID'], 0, 34));
$store[$bcid] = str_replace($u1['keyid'], $gone['keyid'], $store[$bcid]);
check('the gateway returns another block for the footer CID: invalid', fw_verify($ok2, $get, $rootSha)['status'] === 'invalid');

check('User1 certificate revoked: invalid', fw_verify(release($gone, $u2, $pub), $get, $rootSha)['status'] === 'invalid');
check('the User1 key in the User2 place: invalid', fw_verify(release($u1, $u1 + ['keyid' => $u1['keyid']], $pub), $get, $rootSha)['status'] === 'invalid');
check('User2 certificate with the publisher EKU: invalid', fw_verify(release($u1, $wrongEku, $pub), $get, $rootSha)['status'] === 'invalid');
check('publisher key without a Signer CA certificate: invalid', fw_verify(release($u1, $u2, $uncert), $get, $rootSha)['status'] === 'invalid');
check('signed by another key than the footer publisher: invalid', fw_verify(release($u1, $u2, $pub, $uncert), $get, $rootSha)['status'] === 'invalid');

// ---- key lookup by keyid or SKID
check('skid: User1 by keyid', fw_skid($u1['keyid'], $rootSha) === ['known' => true, 'role' => 'User1']);
check('skid: User2 by SKID (SHA-1)', fw_skid($u2['ski'], $rootSha) === ['known' => true, 'role' => 'User2']);
check('skid: publisher by keyid', fw_skid($pub['keyid'], $rootSha) === ['known' => true, 'role' => 'Publisher']);
check('skid: revoked key unknown', fw_skid($gone['keyid'], $rootSha) === ['known' => false]);
check('skid: random key unknown', fw_skid(hash('sha256', 'x'), $rootSha) === ['known' => false]);
check('skid: real root pinned (test PKI): unknown', fw_skid($u1['keyid']) === ['known' => false]);

// ---- the firmware CAs are listed apart from the device CAs
check('pki_list(FW_CA): root + Signer CA', count(pki_list(FW_CA)) === 2);
check('pki_list(PKI_CA) has no Signer CA', !array_filter(pki_list(PKI_CA), fn ($c) => str_contains($c['pem'], file_get_contents("$tmp/pki/signer-ca.pem"))));

echo $fail ? "$fail FAILED\n" : "ALL OK\n";
exit($fail ? 1 : 0);
