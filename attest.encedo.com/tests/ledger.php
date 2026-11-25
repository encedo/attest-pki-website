<?php
/*
 * Tests of the ledger witness (lib/ledger.php), no web server and no network.
 *   php tests/ledger.php
 * Builds hash-linked blocks and receipts in memory like cloud_signer does, publishes "heads" under a fake IPNS name,
 * and checks what attest accepts: extensions yes; forks, rewinds and lying gateways no (alarm, old history kept).
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';
require __DIR__ . '/../lib/firmware.php';

$tmp = sys_get_temp_dir() . '/attest_ledger_' . getmypid();
@mkdir($tmp, 0777, true);
putenv("ATTEST_LEDGER=$tmp");
register_shutdown_function(fn () => exec('rm -rf ' . escapeshellarg($tmp)));

$fail = 0;
function check(string $what, bool $ok): void { global $fail; echo ($ok ? 'OK   ' : 'FAIL ') . $what . "\n"; if (!$ok) $fail++; }

const IPNS = 'k51testtesttesttesttesttesttesttesttesttesttesttesttest';
$store = []; $calls = 0;
$get = function (string $ref, int $max) use (&$store, &$calls): ?string { $calls++; return isset($store[$ref]) && strlen($store[$ref]) <= $max ? $store[$ref] : null; };
function put(string $data): string { global $store; $c = fw_cidv0($data); $store[$c] = $data; return $c; }
function head(int $bs, string $bc, int $rs, string $rc): void {
    global $store;
    $store[IPNS] = json_encode(['headVersion' => 1, 'blockSequence' => $bs, 'blockCID' => $bc, 'receiptSequence' => $rs, 'receiptCID' => $rc]);
}
function block(int $seq, string $prev): string {
    return put(json_encode(['blockVersion' => 1, 'blockSequence' => $seq, 'prevBlockCID' => $prev, 'payload' => ['ts' => $seq]]));
}
function receipt(int $seq, string $prev, string $block, string $img, ?array $confirm = null): string {
    $r = ['receiptVersion' => $confirm ? 2 : 1, 'receiptSequence' => $seq, 'prevReceiptCID' => $prev, 'ledgerBlockSequence' => $seq,
          'ledgerBlockCID' => $block, 'signedFileCID' => fw_cidv0($img), 'signedFileSha512' => hash('sha512', $img), 'source' => 'execute'];
    if ($confirm) $r['user1Confirm'] = $confirm;
    return put(json_encode($r));
}

// genesis + 2 signings (receipt 1 v1, receipt 2 v2 with User1's approval)
$cnf = "$tmp/o.cnf"; file_put_contents($cnf, "[req]\ndistinguished_name = dn\n[dn]\n");
$u1key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
$u1 = ['keyid' => str_repeat('a', 64), 'pem' => openssl_pkey_get_details($u1key)['key']];
$img1 = random_bytes(1000); $img2 = random_bytes(1000);
$g = block(0, 'GENESYS'); $b1 = block(1, $g); $b2 = block(2, $b1);
$r1 = receipt(1, 'GENESIS', $b1, $img1);
$approve = function (string $sid, string $img) use ($u1key) { openssl_sign('encedo-signer-confirm:v1:' . $sid . ':' . hash('sha512', substr($img, 0, -64), true), $s, $u1key, OPENSSL_ALGO_SHA256); return bin2hex($s); };
$r2 = receipt(2, $r1, $b2, $img2, ['sessionId' => 'abc-defg-hij', 'keyid' => $u1['keyid'], 'sig' => $approve('abc-defg-hij', $img2)]);
head(2, $b2, 2, $r2);

$s = ledger_sync($get, true, IPNS);
check('first pull: history from the genesis', $s['head']['blockCID'] === $b2 && count($s['blocks']) === 3 && count($s['receipts']) === 2 && $s['alarm'] === null);
check('image -> receipt index', ($s['files'][fw_cidv0($img2)] ?? '') === $r2);

// rate limit: an unknown block pulls at most once per LEDGER_PULL_EVERY
$calls = 0; [$st] = ledger_block_state(str_repeat('Q', 46), $get, IPNS);
check('unknown block right after a pull: not_in_ledger, no new pull', $st === 'not_in_ledger' && $calls === 0);

// a new signing extends the history
$img3 = random_bytes(1000); $b3 = block(3, $b2); $r3 = receipt(3, $r2, $b3, $img3, ['sessionId' => 'bbb-cccc-ddd', 'keyid' => $u1['keyid'], 'sig' => $approve('bbb-cccc-ddd', $img3)]);
head(3, $b3, 3, $r3);
$s = ledger_sync($get, true, IPNS);
check('extension accepted', $s['head']['blockCID'] === $b3 && isset($s['blocks'][$b3]) && $s['alarm'] === null);

// approvals from receipts
check('approval v2 verified', ledger_approval($s, fw_cidv0($img3), $img3, $b3, $u1, $get) === 'verified');
check('receipt v1: not_recorded', ledger_approval($s, fw_cidv0($img1), $img1, $b1, $u1, $get) === 'not_recorded');
check('approval for another key id: invalid', ledger_approval($s, fw_cidv0($img3), $img3, $b3, ['keyid' => str_repeat('b', 64)] + $u1, $get) === 'invalid');
$other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
check('approval checked with another key: invalid', ledger_approval($s, fw_cidv0($img3), $img3, $b3, ['pem' => openssl_pkey_get_details($other)['key']] + $u1, $get) === 'invalid');
check('image not in the ledger: not_recorded', ledger_approval($s, fw_cidv0('x'), 'x', $b3, $u1, $get) === 'not_recorded');

// fork: a head whose chain does not contain the known head (block 3 replaced)
$b3x = block(3, $b2); $store[$b3x] = $store[$b3x];
$b3x = put(json_encode(['blockVersion' => 1, 'blockSequence' => 3, 'prevBlockCID' => $b2, 'payload' => ['ts' => 'other']]));
$b4x = block(4, $b3x); $r4x = receipt(4, $r3, $b4x, random_bytes(100));
head(4, $b4x, 4, $r4x);
$s = ledger_sync($get, true, IPNS);
check('fork (block 3 replaced): refused, alarm, old head kept', $s['head']['blockCID'] === $b3 && !isset($s['blocks'][$b4x]) && str_contains((string)($s['alarm']['why'] ?? ''), 'fork'));

// rewind
head(2, $b2, 2, $r2);
$s = ledger_sync($get, true, IPNS);
check('rewind to an older head: refused, alarm', $s['head']['blockCID'] === $b3 && ($s['alarm']['why'] ?? '') === 'head goes back');

// the gateway returns other content for a block CID
$b4 = block(4, $b3); $r4 = receipt(4, $r3, $b4, random_bytes(100));
$saved = $store[$b4]; $store[$b4] = str_replace('"blockSequence":4', '"blockSequence":4 ', $saved);
head(4, $b4, 4, $r4);
$s = ledger_sync($get, true, IPNS);
check('block content not matching its CID: refused, alarm', $s['head']['blockCID'] === $b3 && str_contains((string)($s['alarm']['why'] ?? ''), 'not its CID'));

// a receipt naming a block outside the ledger
$store[$b4] = $saved; $rbad = receipt(4, $r3, block(9, $g), random_bytes(100));
head(4, $b4, 4, $rbad);
$s = ledger_sync($get, true, IPNS);
check('receipt naming a block outside the ledger: refused, alarm', $s['head']['blockCID'] === $b3 && str_contains((string)($s['alarm']['why'] ?? ''), 'outside'));

// the honest next head is still accepted after the alarms
head(4, $b4, 4, $r4);
$s = ledger_sync($get, true, IPNS);
check('honest extension after alarms: accepted', $s['head']['blockCID'] === $b4 && isset($s['blocks'][$b4]));

// no state dir: unavailable, nothing written
putenv('ATTEST_LEDGER=' . $tmp . '/missing');
[$st] = ledger_block_state($b4, $get, IPNS);
check('no ledger dir: unavailable', $st === 'unavailable');

echo $fail ? "$fail FAILED\n" : "ALL OK\n";
exit($fail ? 1 : 0);
