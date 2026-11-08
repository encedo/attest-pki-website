<?php
/*
 * attest.encedo.com - stateless attestation JWT validation (DEV-498).
 *   GET  /                 form: paste a JWT (and optionally the device certificate), Validate
 *   POST /                 form result: status + JWT content table (+ device certificate)
 *   POST /v1/validate      {"jwt": "...", "crt": "..."?} -> {"status": "valid|valid_unverified|invalid", "expired": bool, "assurance": "hard|soft" (with valid, DEV-509)}
 *   GET  /v1/skid/<hex>    {"known": bool}  (SHA-1 or SHA-256 of 04||x||y of the device key)
 *   GET  /v1/pki           {"certificates": [...]}  Encedo CA certificates for offline chain validation
 * Run: php -d extension=pdo_sqlite -S localhost:8080 public/index.php
 * Nothing is stored and no JWT is logged; failures never say why.
 */
require __DIR__ . '/../lib/verify.php';
require __DIR__ . '/../lib/store.php';
require __DIR__ . '/../lib/pki.php';

// Every answer carries Content-Length: the body is buffered and measured before anything
// is sent (the PHP built-in server would otherwise answer chunked / close-delimited).
ob_start();
register_shutdown_function(function () {
    $code = http_response_code();
    if (!headers_sent() && $code !== 204 && $code !== 304) header('Content-Length: ' . ob_get_length());
    ob_end_flush();
});

const MAX_BODY = 24576;   // an ML-DSA-87 key PoP token (~11 KB) + the device certificate, form-encoded

function send_json(int $code, array $data, bool $cors = false): void {
    http_response_code($code);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    if ($cors) header('Access-Control-Allow-Origin: *');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
}

function read_body(): ?string {
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_BODY) return null;
    $b = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
    return ($b === false || strlen($b) > MAX_BODY) ? null : $b;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/v1/validate') {
    // CORS: the SDK calls this from a browser page; nothing is stored and no cookie is read, so any origin may ask
    if ($method === 'OPTIONS') {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Max-Age: 86400');
        http_response_code(204);
        exit;
    }
    if ($method !== 'POST') { send_json(405, ['error' => 'method'], true); exit; }
    $b = read_body();
    if ($b === null) { send_json(413, ['error' => 'too large'], true); exit; }
    $in = json_decode($b, true);
    if (!is_array($in) || !is_string($in['jwt'] ?? null) || (isset($in['crt']) && !is_string($in['crt']))) { send_json(400, ['error' => 'expected {"jwt": "...", "crt": "..." (optional)}'], true); exit; }
    $r = attest_check($in['jwt']);
    $cert = ($r['ok'] && isset($in['crt'])) ? device_cert_check($in['crt'], $r['point']) : null;
    send_json(200, attest_status($r, $cert), true);
    exit;
}
if (preg_match('#^/v1/skid/([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$#', $path, $m)) {
    if ($method === 'OPTIONS') { header('Access-Control-Allow-Origin: *'); http_response_code(204); exit; }
    send_json(200, ['known' => skid_lookup(strtolower($m[1])) === 'known'], true);
    exit;
}
if ($path === '/v1/pki') {
    if ($method === 'OPTIONS') { header('Access-Control-Allow-Origin: *'); http_response_code(204); exit; }
    send_json(200, ['certificates' => pki_list()], true);
    exit;
}
if ($path !== '/') { send_json(404, ['error' => 'not found']); exit; }
if ($method !== 'GET' && $method !== 'POST') { send_json(405, ['error' => 'method']); exit; }

// ------------------------------------------------------------------ form
$jwt = ''; $crt = ''; $res = null; $st = null; $cert = null;
if ($method === 'POST') {
    $b = read_body();
    if ($b === null) http_response_code(413);
    else {
        parse_str($b, $f);
        $jwt = is_string($f['jwt'] ?? null) ? $f['jwt'] : '';
        $crt = is_string($f['crt'] ?? null) ? $f['crt'] : '';
    }
    if (trim($jwt) !== '') {
        $res = attest_check($jwt);
        if ($res['ok'] && trim($crt) !== '') $cert = device_cert_check($crt, $res['point']);
        $st = attest_status($res, $cert);
    }
}

function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function when(int $t, int $now): string {
    $d = $t - $now; $a = abs($d);
    $rel = $a < 120 ? "$a s" : ($a < 7200 ? round($a / 60) . ' min' : ($a < 172800 ? round($a / 3600) . ' h' : round($a / 86400) . ' days'));
    return gmdate('Y-m-d H:i:s', $t) . ' UTC (' . ($d >= 0 ? "in $rel" : "$rel ago") . ')';
}
function val(mixed $v): string {   // scalar or small array as text
    if (is_bool($v)) return $v ? 'true' : 'false';
    if (is_array($v)) return $v === [] ? '[]' : (array_is_list($v) && !array_filter($v, 'is_array') ? implode(', ', array_map('strval', $v)) : json_encode($v, JSON_UNESCAPED_SLASHES));
    return (string)$v;
}
function rows(array $kv): string {
    $o = '';
    foreach ($kv as $k => $v) $o .= '<tr><th scope="row">' . h($k) . '</th><td>' . $v . '</td></tr>';
    return $o;
}
function flat(array $a, string $pfx = ''): array {   // key.pubkey.primary style keys
    $o = [];
    foreach ($a as $k => $v) {
        if (is_array($v) && !array_is_list($v)) $o += flat($v, "$pfx$k.");
        else $o[$pfx . $k] = '<code>' . h(val($v)) . '</code>';
    }
    return $o;
}
function table(string $title, array $kv): string { return '<h2 class="eyebrow">' . h($title) . '</h2><div class="tbl"><table>' . rows($kv) . '</table></div>'; }

$now = time();
$tables = '';
if ($res && $res['body'] !== null && $res['hdr'] !== null) {
    $hd = $res['hdr']; $bd = $res['body'];
    $t = ['alg' => '<code>' . h(val($hd['alg'] ?? '')) . '</code>', 'typ' => '<code>' . h(val($hd['typ'] ?? '')) . '</code>',
          'kid' => '<code>' . h(val($hd['kid'] ?? '')) . '</code>'];
    if ($res['skid1']) $t['device key (jwk)'] = 'EC P-256, SHA-1 <code>' . h($res['skid1']) . '</code>';
    $tables .= table('Header', $t);
    $c = [];
    foreach (['iss', 'aud', 'nonce', 'jti'] as $k) if (isset($bd[$k])) $c[$k] = '<code>' . h(val($bd[$k])) . '</code>';
    if (is_int($bd['iat'] ?? null)) $c['iat'] = h(when($bd['iat'], $now));
    if (is_int($bd['exp'] ?? null)) $c['exp'] = h(when($bd['exp'], $now));
    $tables .= table('Claims', $c);
    if (is_array($bd['device'] ?? null)) $tables .= table('Device', flat($bd['device']));
    if ($cert && $cert['cert']) {
        $ce = $cert['cert'];
        $chk = match ($cert['state']) {
            'ok' => isset($ce['board'])   // DEV-509: EPA HEM certificate signed by its board (X.509 path broken on purpose)
                ? '<span class="ok">verified</span>: signed by the board ' . h($ce['board']['subject']) . ' → ' . h($ce['board']['issuer']) . ' (HEM EPA) → Attestation CA → Root CA, CRLs checked'
                : '<span class="ok">verified</span>: ' . h($ce['issuer']) . ' (HEM ' . h($ce['model']) . ') → Attestation CA → Root CA, CRLs checked',
            'revoked' => '<span class="no">revoked</span> (CRL)',
            'unavailable' => 'not checked: the Encedo PKI is not available on this server',
            default => $ce['key_match'] ? '<span class="no">not issued by the Encedo PKI</span>' : '<span class="no">another key than the token (jwk)</span>',
        };
        $tables .= table('Device certificate', ['subject' => '<code>' . h($ce['subject']) . '</code>', 'issuer' => h($ce['issuer']), 'serial' => '<code>' . h($ce['serial']) . '</code>',
            'issued' => h(gmdate('Y-m-d', (int)$ce['from'])), 'notAfter' => h(gmdate('Y-m-d', (int)$ce['to'])) . ' <span class="dim">(does not limit validity: a HEM cannot renew its certificate)</span>',
            'key = jwk' => $ce['key_match'] ? '<span class="ok">yes</span>' : '<span class="no">no</span>', 'chain' => $chk]
            + (isset($cert['assurance']) ? ['assurance' => h($cert['assurance']) . ' <span class="dim">(' . ($cert['assurance'] === 'hard' ? 'secure element in every HEM' : 'EPA module: one secure element for the board') . ')</span>'] : []));   // DEV-509
        if (isset($ce['board'])) $tables .= table('Board certificate', ['subject' => '<code>' . h($ce['board']['subject']) . '</code>', 'issuer' => h($ce['board']['issuer']), 'serial' => '<code>' . h($ce['board']['serial']) . '</code>']);   // DEV-509
    } elseif ($cert) {
        $tables .= table('Device certificate', ['input' => '<span class="no">not a certificate</span>']);
    }
    if (is_array($bd['key'] ?? null)) {
        $k = $bd['key'];
        foreach (['created', 'updated'] as $x) if (is_int($k[$x] ?? null)) $k[$x] = gmdate('Y-m-d H:i:s', $k[$x]) . ' UTC';
        $tables .= table('Key', flat($k));
    }
    if (is_array($bd['pop'] ?? null)) {
        [$pm, $pr] = $res['pop'];
        $p = flat($bd['pop']);
        if ($res['ok']) $p['result'] = $pm === 'signature' ? 'signature verified with key.pubkey.primary' : 'MAC proof: checked by the party that sent pop_args (needs its ephemeral secret)';
        $tables .= table('Proof of possession', $p);
    }
}

$verdict = '';
if ($st) {
    $s = $st['status']; $exp = $st['expired'] ?? false; $byCert = $cert && $cert['state'] === 'ok';
    $how = $byCert ? (isset($cert['cert']['board']) ? 'The HEM certificate is signed by an EPA module whose board certificate chains to the Encedo Root CA; nothing is revoked.' : 'The device certificate chains to the Encedo Root CA and is not revoked.') : 'Its device key is known to Encedo.';   // DEV-509
    if (isset($st['assurance'])) $how .= ' Assurance: ' . $st['assurance'] . '.';   // DEV-509
    [$cls, $title, $text] = match (true) {
        $s === 'invalid' => ['bad', 'Invalid', 'This is not a valid Encedo attestation' . ($cert ? ' for this device certificate.' : '.')],
        $s === 'valid' && !$exp => ['good', 'Valid', "Signed by a genuine Encedo device. $how"],
        $s === 'valid' => ['good', 'Valid, token expired', "Signed by a genuine Encedo device. $how The token is past its exp time."],
        !$exp => ['plain', 'Signature valid, device not verified', 'The token is intact. Add the device certificate (crt) to check the device against the Encedo PKI.'],
        default => ['plain', 'Signature valid, device not verified, token expired', 'The token is intact but past its exp time. Add the device certificate (crt) to check the device.'],
    };
    $verdict = "<div class=\"verdict $cls\" role=\"status\"><p class=\"eyebrow\">Result</p><strong>" . h($title) . '</strong><span>' . h($text) . '</span></div>';
    if ($s === 'invalid' && $tables !== '') $tables = '<p class="note">Content as sent; not trusted.</p>' . $tables;
} elseif ($method === 'POST') {
    $verdict = '<div class="verdict bad" role="status"><p class="eyebrow">Result</p><strong>Nothing to validate</strong><span>Paste an attestation JWT.</span></div>';
}

$pkiNote = '';
if (pki_ready()) {
    $n = []; foreach (crl_info() as $c) $n[] = h($c['issuer']) . ': next update ' . h(gmdate('Y-m-d', $c['next']));
    $pkiNote = '<p class="dim small">CRLs in use: ' . implode(' · ', $n) . '</p>';
}

$css = <<<'CSS'
:root{--ground:#F1F4F3;--surface:#FFFFFF;--sunken:#E7EBE9;--ink:#0F1414;--ink-soft:#3A4746;--muted:#6A7773;--rule:#D5DCD9;--rule-firm:#A9B5B1;
 --sealed:#0F5F4B;--sealed-soft:#E0EFE9;--sealed-line:#96C6B5;--exposed:#94422A;--exposed-soft:#F5E6E0;
 --shadow-lg:0 2px 4px rgba(15,20,20,.04),0 18px 44px -22px rgba(15,20,20,.30);
 --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;--serif:Georgia,"Iowan Old Style","Palatino Linotype",ui-serif,serif}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--ground:#0A0E0E;--surface:#121918;--sunken:#060909;--ink:#E8F0ED;--ink-soft:#AFBDB8;--muted:#7C8C87;--rule:#232D2C;--rule-firm:#3A4644;
 --sealed:#47C6A3;--sealed-soft:#102E27;--sealed-line:#2C6858;--exposed:#DE8467;--exposed-soft:#2C1B15;--shadow-lg:0 2px 4px rgba(0,0,0,.4),0 20px 50px -24px rgba(0,0,0,.85);color-scheme:dark}}
:root[data-theme="dark"]{--ground:#0A0E0E;--surface:#121918;--sunken:#060909;--ink:#E8F0ED;--ink-soft:#AFBDB8;--muted:#7C8C87;--rule:#232D2C;--rule-firm:#3A4644;
 --sealed:#47C6A3;--sealed-soft:#102E27;--sealed-line:#2C6858;--exposed:#DE8467;--exposed-soft:#2C1B15;--shadow-lg:0 2px 4px rgba(0,0,0,.4),0 20px 50px -24px rgba(0,0,0,.85);color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:17px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:1140px;margin:0 auto;padding:0 32px}
@media (max-width:640px){.wrap{padding:0 16px}}
h1,h2,p{margin:0}
a{color:var(--sealed);text-underline-offset:3px;text-decoration-thickness:1px}
a:focus-visible,textarea:focus-visible,button:focus-visible{outline:2px solid var(--sealed);outline-offset:3px}
.masthead{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:26px 0 0;font:12px var(--mono);letter-spacing:.04em;color:var(--muted)}
.masthead b{color:var(--ink);font-weight:500;letter-spacing:.02em}
.eyebrow{font:11.5px var(--mono);letter-spacing:.17em;text-transform:uppercase;color:var(--sealed)}
.hero{padding:72px 0 48px;display:flex;flex-direction:column;gap:18px}
h1{font-size:clamp(36px,5.2vw,56px);line-height:1.05;letter-spacing:-.035em;font-weight:620;text-wrap:balance}
h1 .quiet{color:var(--muted)}
.lede{font:20px/1.55 var(--serif);color:var(--ink-soft);max-width:66ch}
form{background:var(--surface);border:1px solid var(--rule);border-radius:5px;padding:22px;box-shadow:var(--shadow-lg);display:flex;flex-direction:column;gap:16px}
label{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-weight:600;font-size:15px;margin-bottom:6px}
label small{font-weight:400;color:var(--muted);font-size:13px}
textarea{width:100%;min-height:140px;resize:vertical;padding:12px;border:1px solid var(--rule-firm);border-radius:6px;background:var(--ground);color:var(--ink);font:12.5px/1.45 var(--mono);word-break:break-all}
textarea#crt{min-height:84px}
.actions{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.actions small{color:var(--muted);font-size:13px}
button{font:600 15px var(--sans);padding:10px 22px;border:0;border-radius:6px;background:var(--sealed);color:var(--surface);cursor:pointer}
.verdict{display:flex;flex-direction:column;gap:4px;margin:28px 0 8px;padding:18px 20px;border-radius:5px;border:1px solid var(--rule-firm);background:var(--surface)}
.verdict strong{font-size:22px;letter-spacing:-.01em}
.verdict span{color:var(--ink-soft)}
.verdict.good{background:var(--sealed-soft);border-color:var(--sealed-line)}.verdict.good strong{color:var(--sealed)}
.verdict.bad{background:var(--exposed-soft);border-color:var(--exposed)}.verdict.bad strong,.verdict.bad .eyebrow{color:var(--exposed)}
.verdict.plain .eyebrow{color:var(--muted)}
h2.eyebrow{margin:30px 0 8px}
.tbl{overflow-x:auto;border:1px solid var(--rule);border-radius:5px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;vertical-align:top;padding:8px 14px;border-bottom:1px solid var(--rule)}
tr:last-child th,tr:last-child td{border-bottom:0}
th{width:28%;font-weight:600;white-space:nowrap;color:var(--ink-soft)}
code{font:12.5px var(--mono);background:var(--sunken);padding:1px 5px;border-radius:3px;overflow-wrap:anywhere}
.ok{color:var(--sealed);font-weight:600}.no{color:var(--exposed);font-weight:600}
.dim{color:var(--muted)}.small{font-size:13px}.note{color:var(--muted);font-size:14px;margin:12px 0 0}
section{padding:72px 0 0;margin-top:72px;border-top:1px solid var(--rule)}
section h2{font-size:clamp(26px,3.2vw,36px);line-height:1.14;letter-spacing:-.025em;font-weight:600;margin:12px 0 28px;text-wrap:balance}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:28px 40px}
.step{border-top:2px solid var(--sealed-line);padding-top:18px;font-size:15.5px;color:var(--ink-soft)}
.step b{display:block;color:var(--ink);font-size:19px;font-weight:620;letter-spacing:-.01em;margin:8px 0 8px}
.step .eyebrow{display:block;font-size:11px}
section .dim.small{margin-top:14px}
dl.api{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:0;font-size:15px}
dl.api dt{font:13px var(--mono);color:var(--ink);padding-top:2px}dl.api dd{margin:0;color:var(--ink-soft)}
@media (max-width:640px){dl.api{grid-template-columns:1fr}dl.api dd{margin-bottom:8px}}
footer{margin-top:88px;border-top:1px solid var(--rule);padding:30px 0 60px}
footer .wrap{display:flex;flex-wrap:wrap;gap:12px 28px;align-items:center}
footer a{font:12.5px var(--mono);color:var(--muted);text-decoration:none}
footer a:hover{color:var(--ink)}
footer .spacer{flex:1}
CSS;
$icon = 'data:image/svg+xml,' . rawurlencode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="13" fill="#0F5F4B"/><rect x="16" y="16" width="32" height="32" rx="7" fill="none" stroke="#AFD2C5" stroke-width="4"/><path d="M24 33l6 6 11-12" fill="none" stroke="#F2F8F5" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>');
$cspHash = base64_encode(hash('sha256', $css, true));
header('Content-Type: text/html; charset=utf-8');
header("Content-Security-Policy: default-src 'none'; style-src 'sha256-$cspHash'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Encedo Attestation</title><link rel="icon" href="<?= h($icon) ?>"><style><?= $css ?></style></head>
<body>
<div class="wrap">
  <div class="masthead">
    <span><b>encedo</b> &nbsp;attestation check</span>
    <span>attest.encedo.com &middot; HEM device attestation</span>
  </div>
  <div class="hero">
    <p class="eyebrow">Encedo HEM &middot; attestation</p>
    <h1>Check the device,<br><span class="quiet">not our word for it.</span></h1>
    <p class="lede">Paste the token an Encedo HEM returned for <code>POST /api/system/config/attestation</code> and, to check the device itself, its certificate from <code>GET /api/system/config/attestation</code>. Nothing you paste is stored.</p>
  </div>

  <form method="post" action="/">
    <div>
      <label for="jwt">Attestation JWT <small>the bare JWT or the whole <code>{"attestation": "..."}</code> reply</small></label>
      <textarea id="jwt" name="jwt" spellcheck="false" autocomplete="off" placeholder="eyJhbGciOiJFUzI1NiIs..." required><?= h($jwt) ?></textarea>
    </div>
    <div>
      <label for="crt">Device certificate <small>optional &middot; <code>crt</code> (base64 DER), PEM, or the whole <code>GET</code> reply</small></label>
      <textarea id="crt" name="crt" spellcheck="false" autocomplete="off" placeholder="MIICJDCCAcqgAwIBAgI..."><?= h($crt) ?></textarea>
    </div>
    <div class="actions"><button type="submit">Validate</button><small>The certificate is checked against the Encedo PKI: chain, CRLs, and its key against the token.</small></div>
  </form>

  <?= $verdict ?>
  <?= $tables ?>

  <section>
    <p class="eyebrow">How it is checked</p>
    <h2>Three things, each one you can repeat yourself.</h2>
    <div class="steps">
      <div class="step"><span class="eyebrow">1 &middot; token</span><b>Signed by the device key</b>ES256 with the key in the header (<code>jwk</code>), <code>kid</code> = hash of that key, issuer, audience, nonce, time window.</div>
      <div class="step"><span class="eyebrow">2 &middot; device</span><b>Certified by Encedo</b>The certificate key equals <code>jwk</code>, the chain ends at the Encedo Root CA (SHA-256 <code>b28f4ee4&hellip;6e9c</code>), no CA has revoked it. Its date does not limit validity.</div>
      <div class="step"><span class="eyebrow">3 &middot; key</span><b>Proof of possession</b>A signature PoP is verified with the attested key. A MAC PoP (ECDH, KEM) needs the verifier's ephemeral secret and is checked by the party that asked.</div>
    </div>
    <?= $pkiNote ?>
  </section>

  <section>
    <p class="eyebrow">Integration</p>
    <h2>The same checks over HTTP.</h2>
    <dl class="api">
      <dt>POST /v1/validate</dt><dd><code>{"jwt": "...", "crt": "..."}</code> (crt optional) &rarr; <code>{"status": "valid" | "valid_unverified" | "invalid", "expired": bool, "assurance": "hard" | "soft"}</code> (assurance with valid: hard = HEM PPA, soft = HEM EPA)</dd>
      <dt>GET /v1/skid/&lt;hex&gt;</dt><dd>Is a device key (SHA-1 or SHA-256 of <code>04&#8214;x&#8214;y</code>) known to Encedo: <code>{"known": bool}</code></dd>
      <dt>GET /v1/pki</dt><dd>The Encedo CA certificates for offline validation; CRLs and fingerprints at <a href="https://pki.encedo.com/">pki.encedo.com</a></dd>
    </dl>
  </section>
</div>

<footer>
  <div class="wrap">
    <a href="https://pki.encedo.com/">pki.encedo.com</a>
    <a href="https://github.com/encedo/attest-pki-website">Source (MIT)</a>
    <a href="https://encedo.com/">Encedo</a>
    <span class="spacer"></span>
    <a href="https://rkv.pl">RKV</a>
  </div>
</footer>
</body></html>
