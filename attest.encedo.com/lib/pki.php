<?php
/*
 * The device certificate against the Encedo PKI (https://pki.encedo.com, synced by tools/sync_pki.php):
 *   chain device -> issuing CA -> Encedo Attestation CA -> Encedo Root CA (pinned by SHA-256 of its DER),
 *   CRLs of all four CAs, and the certificate key = the jwk of the token.
 * Two issuing CAs, one per HEM model: Encedo Custody CA signs HEM PPA, Encedo EPA Custody CA signs HEM EPA.
 * The device certificate's authorityKeyIdentifier picks the issuing CA; openssl verify then checks the signatures.
 * The certificate date does not limit validity: a HEM cannot renew its certificate, so only the CA signatures and the CRLs count
 * (openssl verify -no_check_time).
 */

const ROOT_SHA256 = 'b28f4ee4cf26028260cf4f0db18bd2fb7234d172925797dca7f81e53a2816e9c';   // Encedo Root CA, DER
const PKI_CA = ['root-ca', 'attestation-ca', 'custody-ca', 'epa-custody-ca'];
const PKI_ISSUING = ['custody-ca' => 'PPA', 'epa-custody-ca' => 'EPA'];   // issuing CA -> HEM model it signs
const MAX_CRT = 4096;

function pem_to_der(string $pem): ?string {
    if (!preg_match('/-----BEGIN [A-Z0-9 ]+-----(.+?)-----END [A-Z0-9 ]+-----/s', $pem, $m)) return null;
    $d = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
    return $d === false ? null : $d;
}

// openssl CLI with an argument list: [exit code, stdout + stderr]
function ossl_run(array $args): array {
    $cmd = escapeshellarg(ossl_bin()); foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) return [1, 'openssl not started'];
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
    return [proc_close($p), trim($out)];
}

function crl_args(string $dir): array {
    $a = []; foreach (PKI_CA as $n) { $a[] = '-CRLfile'; $a[] = "$dir/$n.crl.pem"; }
    return $a;
}

// true when the synced PKI is complete and its root is the pinned one
function pki_ready(): bool {
    $d = data_dir();
    foreach (PKI_CA as $n) if (!is_file("$d/pki/$n.pem") || !is_file("$d/crl/$n.crl.pem")) return false;
    $der = pem_to_der((string)file_get_contents("$d/pki/root-ca.pem"));
    return $der !== null && hash_equals(ROOT_SHA256, hash('sha256', $der));
}

// [{issuer, next (unix), revoked (count)}] of the synced CRLs
function crl_info(): array {
    $out = [];
    foreach (PKI_CA as $n) {
        $f = data_dir() . "/crl/$n.crl.pem";
        if (!is_file($f)) continue;
        [$rc, $t] = ossl_run(['crl', '-in', $f, '-noout', '-text']);
        if ($rc !== 0) continue;
        preg_match('/Issuer:.*CN\s*=\s*([^,\n]+)/', $t, $is); preg_match('/Next Update:\s*(.+)/', $t, $nx);
        $out[] = ['issuer' => trim($is[1] ?? $n), 'next' => isset($nx[1]) ? (int)strtotime(trim($nx[1])) : 0, 'revoked' => preg_match_all('/Serial Number:/', $t)];
    }
    return $out;
}

// the certificate as PEM from: PEM, base64 DER, or the whole GET /api/system/config/attestation reply ({"crt": ...}); null if none
function crt_parse(string $in): ?string {
    $in = trim($in);
    $j = json_decode($in, true); if (is_array($j) && is_string($j['crt'] ?? null)) $in = trim($j['crt']);
    $der = str_contains($in, '-----BEGIN') ? pem_to_der($in) : base64_decode(preg_replace('/\s+/', '', $in), true);
    if (!is_string($der) || $der === '' || strlen($der) > MAX_CRT) return null;
    $pem = pem($der, 'CERTIFICATE');
    return @openssl_x509_read($pem) ? $pem : null;
}

// a key identifier from openssl_x509_parse ("keyid:83:C8:..." or "83:C8:...") as lowercase hex
function key_id_hex(string $s): string {
    return strtolower(preg_replace('/[^0-9a-f]/i', '', preg_replace('/^\s*keyid:/i', '', strtok($s, "\n") ?: '')));
}

// the issuing CA the certificate names in its authorityKeyIdentifier: [name, model], or null if it is none of ours
function issuing_ca(array $parsed): ?array {
    $aki = key_id_hex($parsed['extensions']['authorityKeyIdentifier'] ?? '');
    if ($aki === '') return null;
    foreach (PKI_ISSUING as $n => $model) {
        $ca = @openssl_x509_parse((string)@file_get_contents(data_dir() . "/pki/$n.pem"));
        if ($ca && key_id_hex($ca['extensions']['subjectKeyIdentifier'] ?? '') === $aki) return [$n, $model];
    }
    return null;
}

// state: 'ok' | 'revoked' | 'invalid' (not a certificate, another key than the token, not issued by the Encedo PKI) | 'unavailable' (PKI not synced)
// cert: what the page shows (null if the input is not a certificate)
function device_cert_check(string $in, ?string $point): array {
    $r = ['state' => 'invalid', 'cert' => null, 'why' => ''];
    $pem = crt_parse($in);
    if ($pem === null) { $r['why'] = 'not a certificate'; return $r; }
    $c = openssl_x509_parse($pem, false);
    $k = @openssl_pkey_get_details(openssl_pkey_get_public($pem));
    $cpt = (isset($k['ec']['x']) && ($k['ec']['curve_name'] ?? '') === 'prime256v1')
        ? "\x04" . str_pad($k['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($k['ec']['y'], 32, "\0", STR_PAD_LEFT) : null;
    $r['cert'] = ['subject' => $c['subject']['commonName'] ?? '', 'issuer' => $c['issuer']['commonName'] ?? '', 'serial' => strtolower($c['serialNumberHex'] ?? ''),
                  'from' => $c['validFrom_time_t'] ?? 0, 'to' => $c['validTo_time_t'] ?? 0, 'skid' => $cpt ? sha1($cpt) : '',
                  'key_match' => $cpt !== null && $point !== null && hash_equals($cpt, $point), 'model' => ''];
    if (!$r['cert']['key_match']) { $r['why'] = 'certificate key != jwk'; return $r; }
    if (!pki_ready()) { $r['state'] = 'unavailable'; return $r; }

    $ica = issuing_ca(openssl_x509_parse($pem));
    if ($ica === null) { $r['why'] = 'issuer: not an Encedo issuing CA'; return $r; }

    $d = data_dir();
    $tmp = tempnam(sys_get_temp_dir(), 'crt'); $chain = tempnam(sys_get_temp_dir(), 'chn');
    file_put_contents($tmp, $pem);
    file_put_contents($chain, file_get_contents("$d/pki/{$ica[0]}.pem") . file_get_contents("$d/pki/attestation-ca.pem"));
    [$rc, $out] = ossl_run(array_merge(['verify', '-no_check_time', '-crl_check_all'], crl_args("$d/crl"), ['-CAfile', "$d/pki/root-ca.pem", '-untrusted', $chain, $tmp]));
    @unlink($tmp); @unlink($chain);
    if ($rc === 0) { $r['state'] = 'ok'; $r['cert']['model'] = $ica[1]; }   // the model only once the chain holds
    elseif (stripos($out, 'revoked') !== false) $r['state'] = 'revoked';
    else $r['why'] = 'chain: ' . $out;
    return $r;
}
