<?php
/*
 * Witness of the cloud_signer ledger (S5): the history attest has seen, read from the IPNS head.
 *
 * cloud_signer publishes head.json {headVersion, blockSequence, blockCID, receiptSequence, receiptCID} under the IPNS name
 * LEDGER_IPNS after every signing. attest pulls it only when it meets a block it does not know (fw_verify) or at deploy
 * (tools/ledger_sync.php) - no cron, no traffic otherwise - at most once per LEDGER_PULL_EVERY seconds.
 *
 * A new head is accepted only when both hash-linked chains (blocks: prevBlockCID, receipts: prevReceiptCID) lead from it back
 * to the head already known, every CID recomputed here (the gateway is not trusted), sequences consecutive. A head that does not
 * extend the known one (fork, rewind, a removed entry) is NOT accepted: the old history stays and an alarm is recorded.
 * The IPNS signature itself is not what is trusted (its key is on the IPFS node); the chain and the ceremony signatures are.
 *
 * State (the one writable place of the service): ATTEST_LEDGER [/ledger]/state.json
 *   head, blocks {cid: seq}, receipts {cid: {seq, file, block, sha512, version}}, files {signed image CID: receipt CID},
 *   pulled (unix), alarm (null | {at, why, head})
 */

const LEDGER_IPNS = 'k51qzi5uqu5die6i5a3gno592mfmnej933qwcr48gnts83snwsedj2581f1mu4';   // key signer-ledger of the ipfs1 node
const LEDGER_PULL_EVERY = 30;          // seconds between two IPNS pulls (rate limit)
const LEDGER_MAX_WALK = 100000;

function ledger_dir(): string { return rtrim(getenv('ATTEST_LEDGER') ?: '/ledger', '/'); }

function ledger_state(): array {
    $s = @json_decode((string)@file_get_contents(ledger_dir() . '/state.json'), true);
    return is_array($s) ? $s : ['head' => null, 'blocks' => [], 'receipts' => [], 'files' => [], 'pulled' => 0, 'alarm' => null];
}

function ledger_save(array $s): bool {
    $f = ledger_dir() . '/state.json';
    return @file_put_contents("$f.new", json_encode($s, JSON_UNESCAPED_SLASHES)) !== false && @rename("$f.new", $f);
}

// gateway read of /ipfs/<cid> or /ipns/<name>
function ledger_get(string $ref, int $max): ?string {
    $path = str_starts_with($ref, 'k51') ? "ipns/$ref" : "ipfs/$ref";
    $url = rtrim(getenv('ATTEST_IPFS_GATEWAY') ?: 'https://ipfs.encedo.com/ipfs/', '/');
    $url = preg_replace('#/ipfs$#', '', $url) . "/$path";
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'header' => "Cache-Control: no-cache\r\n"], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $d = @file_get_contents($url, false, $ctx, 0, $max + 1);
    return ($d === false || strlen($d) > $max) ? null : $d;
}

// a JSON object fetched by CID, its CID recomputed; null if missing or not that content
function ledger_obj(callable $get, string $cid): ?array {
    $d = $get($cid, FW_MAX_BLOCK);
    if ($d === null || fw_cidv0($d) !== $cid) return null;
    $j = json_decode($d, true);
    return is_array($j) ? $j : null;
}

// pull the IPNS head and extend the history; returns the state. $force: ignore the rate limit (deploy)
function ledger_sync(?callable $get = null, bool $force = false, string $ipns = LEDGER_IPNS): array {
    $get ??= 'ledger_get';
    $dir = ledger_dir();
    if (!is_dir($dir)) return ledger_state();
    $lock = @fopen("$dir/lock", 'c');
    if (!$lock || !flock($lock, LOCK_EX)) return ledger_state();
    try {
        $s = ledger_state();
        if (!$force && time() - (int)$s['pulled'] < LEDGER_PULL_EVERY) return $s;
        $s['pulled'] = time();
        $raw = $get($ipns, 4096);
        $h = $raw === null ? null : json_decode($raw, true);
        if (!is_array($h) || ($h['headVersion'] ?? null) !== 1 || !is_int($h['blockSequence'] ?? null) || !is_int($h['receiptSequence'] ?? null)
            || !is_string($h['blockCID'] ?? null) || !is_string($h['receiptCID'] ?? null)) { ledger_save($s); return $s; }
        $known = $s['head'];
        if ($known !== null && $known['blockCID'] === $h['blockCID'] && $known['receiptCID'] === $h['receiptCID']) { ledger_save($s); return $s; }

        $why = null; $blocks = []; $receipts = []; $files = [];
        if ($known !== null && ($h['blockSequence'] < $known['blockSequence'] || $h['receiptSequence'] < $known['receiptSequence'])) $why = 'head goes back';

        // blocks: from the new head back to the known head (or to the genesis on the first pull)
        for ($cid = $h['blockCID'], $seq = $h['blockSequence'], $n = 0; $why === null; $n++) {
            if ($known !== null && $cid === $known['blockCID']) { if ($seq !== $known['blockSequence']) $why = 'block sequence differs at the known head'; break; }
            if ($n > LEDGER_MAX_WALK || $seq < 0) { $why = 'block chain does not reach the known head'; break; }
            $b = ledger_obj($get, $cid);
            if ($b === null) { $why = "block $cid unreadable or not its CID"; break; }
            // the production genesis (2025) spells the key "blockSequ ence" - accepted for the genesis only
            $bseq = $b['blockSequence'] ?? (($b['prevBlockCID'] ?? null) === 'GENESYS' ? ($b['blockSequ ence'] ?? null) : null);
            if ($bseq !== $seq) { $why = "block $cid sequence"; break; }
            $blocks[$cid] = $seq;
            $prev = $b['prevBlockCID'] ?? null;
            if ($prev === 'GENESYS') { if ($known !== null) $why = 'block chain reaches the genesis without the known head (fork)'; break; }
            if (!is_string($prev)) { $why = "block $cid without prevBlockCID"; break; }
            $cid = $prev; $seq--;
        }
        // receipts, the same way; each one must name a block of the history
        for ($cid = $h['receiptCID'], $seq = $h['receiptSequence'], $n = 0; $why === null; $n++) {
            if ($known !== null && $cid === $known['receiptCID']) { if ($seq !== $known['receiptSequence']) $why = 'receipt sequence differs at the known head'; break; }
            if ($cid === 'GENESIS') { if ($known !== null) $why = 'receipt chain reaches GENESIS without the known head (fork)'; break; }
            if ($n > LEDGER_MAX_WALK || $seq < 1) { $why = 'receipt chain does not reach the known head'; break; }
            $r = ledger_obj($get, $cid);
            if ($r === null) { $why = "receipt $cid unreadable or not its CID"; break; }
            if (($r['receiptSequence'] ?? null) !== $seq) { $why = "receipt $cid sequence"; break; }
            $bc = (string)($r['ledgerBlockCID'] ?? '');
            if (!isset($blocks[$bc]) && !isset($s['blocks'][$bc])) { $why = "receipt $cid names a block outside the ledger"; break; }
            $receipts[$cid] = ['seq' => $seq, 'file' => (string)($r['signedFileCID'] ?? ''), 'block' => $bc,
                               'sha512' => (string)($r['signedFileSha512'] ?? ''), 'version' => (int)($r['receiptVersion'] ?? 1)];
            $files[(string)($r['signedFileCID'] ?? '')] = $cid;
            $cid = (string)($r['prevReceiptCID'] ?? '');
            $seq--;
        }

        if ($why !== null) {
            $s['alarm'] = ['at' => time(), 'why' => $why, 'head' => $h];
            error_log("attest ledger ALARM: $why");
        } else {
            $s['head'] = $h;
            $s['blocks'] = ($s['blocks'] ?: []) + $blocks;
            $s['receipts'] = ($s['receipts'] ?: []) + $receipts;
            $s['files'] = ($s['files'] ?: []) + $files;
        }
        ledger_save($s);
        return $s;
    } finally {
        flock($lock, LOCK_UN); fclose($lock);
    }
}

// is the block in the history (pulls the head once when it is not); 'included' | 'not_in_ledger' | 'unavailable'
function ledger_block_state(string $blockCid, ?callable $get = null, string $ipns = LEDGER_IPNS): array {
    $s = ledger_state();
    if (!isset($s['blocks'][$blockCid])) $s = ledger_sync($get, false, $ipns);
    if (isset($s['blocks'][$blockCid])) return ['included', $s];
    return [$s['head'] === null ? 'unavailable' : 'not_in_ledger', $s];
}

// User1's approval of this image from its receipt (receipt v2, variant B):
// 'verified' | 'invalid' | 'not_recorded' (v1 receipt or none)
function ledger_approval(array $s, string $imgCid, string $img, string $blockCid, array $user1, callable $get): string {
    $rc = $s['files'][$imgCid] ?? null;
    if ($rc === null) return 'not_recorded';
    $r = ledger_obj($get, $rc);
    if ($r === null || ($r['signedFileCID'] ?? '') !== $imgCid || ($r['ledgerBlockCID'] ?? '') !== $blockCid
        || ($r['signedFileSha512'] ?? '') !== hash('sha512', $img)) return 'invalid';
    if ((int)($r['receiptVersion'] ?? 1) < 2) return 'not_recorded';
    $c = $r['user1Confirm'] ?? null;
    if (!is_array($c) || ($c['keyid'] ?? '') !== $user1['keyid'] || !is_string($c['sessionId'] ?? null) || !is_string($c['sig'] ?? null)) return 'invalid';
    $sig = @hex2bin($c['sig']);
    // what User1 signed: encedo-signer-confirm:v1:<session>:<final_file_hash>, final_file_hash = sha512 of the image without its signature
    $msg = 'encedo-signer-confirm:v1:' . $c['sessionId'] . ':' . hash('sha512', substr($img, 0, -64), true);
    $key = openssl_pkey_get_public($user1['pem']);
    return ($sig !== false && $key && openssl_verify($msg, $sig, $key, OPENSSL_ALGO_SHA256) === 1) ? 'verified' : 'invalid';
}
