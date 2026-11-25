<?php
/*
 * Pull the cloud_signer ledger head from IPNS now and extend the witnessed history (lib/ledger.php).
 *   php tools/ledger_sync.php
 * Run by deploy/deploy.sh attest after a new container (the service itself pulls only when it meets an unknown block).
 * ATTEST_LEDGER: the writable state dir [/ledger]. Prints the head, the history size and an alarm if there is one.
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';
require __DIR__ . '/../lib/firmware.php';

if (!is_dir(ledger_dir()) || !is_writable(ledger_dir())) { fwrite(STDERR, 'ledger_sync: ' . ledger_dir() . " is not a writable dir\n"); exit(1); }
$s = ledger_sync(null, true);
$h = $s['head'];
echo $h === null ? "ledger: no head (IPNS " . LEDGER_IPNS . " unreadable?)\n"
                 : "ledger: block {$h['blockSequence']} {$h['blockCID']}, receipt {$h['receiptSequence']} {$h['receiptCID']}, "
                   . count($s['blocks']) . ' blocks, ' . count($s['receipts']) . " receipts\n";
if ($s['alarm'] !== null) echo 'ledger ALARM ' . gmdate('Y-m-d H:i', $s['alarm']['at']) . ' UTC: ' . $s['alarm']['why'] . "\n";
