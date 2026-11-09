#!/usr/bin/env python3
"""Watch Certificate Transparency for new public TLS certificates on our domains.

  ct_watch.py run      query the Cert Spotter API for every domain (with subdomains),
                       report every certificate issued since the last run
  ct_watch.py status   the last run and the most recent certificates (for the bot's `ct`)

The first run of a domain only records what is there (a baseline), it reports nothing.
Every later certificate is reported, labelled:
  renewal       the same names from the same issuer as before
  NEW NAME      a name not seen before on this domain
  NEW ISSUER    an issuer (organisation) not seen before on this domain

Alerts go out once per run, all certificates in one message:
  - to Uptime Kuma (push monitor): "down" with a short text when there is something new,
    "up" on a clean run; nothing when the API failed, so Kuma also alarms when the watch
    itself stops working (the monitor's heartbeat interval runs out)
  - to an executable hook, the full text on stdin (e.g. the onchato bot's `notify`)

Files (all optional except the domain list):
  --domains  domains.txt        one domain per line, '#' comments
  --state    /var/lib/ct-watch  state.json (written atomically)
  --conf     /etc/ct-watch      kuma.url (the push URL, a secret), notify (executable hook)

Python 3 standard library only.
"""
import argparse
import calendar
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API = 'https://api.certspotter.com/v1/issuances'
UA = 'ct-watch (attest.encedo.com)'
RECENT = 50          # certificates kept for `status`
SEEN = 2000          # certificate hashes kept to report a certificate once across domains
MAX_PAGES = 20       # per domain and run; the rest waits for the next run


class ApiError(Exception):
    pass


class RateLimited(ApiError):
    """HTTP 429: every further query of this run would be refused as well."""
    def __init__(self, msg, retry_after):
        super().__init__(msg)
        self.retry_after = retry_after


def clean(s, n=200):
    """Text from the API, safe for a log line or a chat message."""
    s = re.sub(r'[\x00-\x1f\x7f-\x9f]', '?', str(s))
    return s if len(s) <= n else s[:n] + '...'


def fetch_api(domain, after, api=API, timeout=60):
    """One page of issuances of the domain and its subdomains, after the given id."""
    q = [('domain', domain), ('include_subdomains', 'true'),
         ('expand', 'dns_names'), ('expand', 'issuer')]
    if after:
        q.append(('after', after))
    req = urllib.request.Request(api + '?' + urllib.parse.urlencode(q), headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited('%s: HTTP 429' % domain, retry_seconds(e.headers.get('Retry-After')))
        raise ApiError('%s: HTTP %d' % (domain, e.code))
    except (OSError, ValueError) as e:
        raise ApiError('%s: %s' % (domain, clean(e, 120)))
    if not isinstance(data, list):
        raise ApiError('%s: unexpected answer' % domain)
    return data


def retry_seconds(v, default=600):
    """Retry-After in seconds (only the numeric form; the API sends it), bounded to 1 min .. 2 h."""
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        n = default
    return max(60, min(n, 7200))


def epoch(ts):
    return calendar.timegm(time.strptime(ts, '%Y-%m-%dT%H:%M:%SZ'))


def stamp(t):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))


def issuer_org(iss):
    return clean((iss or {}).get('friendly_name') or (iss or {}).get('name') or 'unknown', 80)


def load_state(path):
    try:
        with open(path) as f:
            s = json.load(f)
    except FileNotFoundError:
        s = {}
    s.setdefault('domains', {})
    s.setdefault('seen', [])
    s.setdefault('recent', [])
    return s


def save_state(path, s):
    d = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.state.')
    with os.fdopen(fd, 'w') as f:
        json.dump(s, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def scan(domains, state, fetch, now):
    """Bring the state up to date; return (new certificates, errors).

    The domain checked longest ago goes first, so a rate limit hit half-way does not
    starve the same domains every run; after a 429 the run stops asking."""
    new, errors = [], []
    seen = set(state['seen'])
    order = sorted(domains, key=lambda d: state['domains'].get(d, {}).get('checked', ''))
    for i, dom in enumerate(order):
        ds = state['domains'].get(dom)
        baseline = ds is None
        if baseline:
            ds = {'last_id': None, 'names': [], 'issuers': []}
        names, issuers = set(ds['names']), set(ds['issuers'])
        last = ds['last_id']
        found = []
        try:
            for _ in range(MAX_PAGES):
                page = fetch(dom, last)
                if not page:
                    break
                for c in page:
                    cid = str(c['id'])
                    if not cid.isdigit():
                        raise ApiError('%s: bad id' % dom)
                    if last is None or int(cid) > int(last):
                        last = cid
                    found.append(c)
        except RateLimited as e:
            rest = order[i + 1:]
            errors.append(clean(e) + ('; not asked: ' + ', '.join(rest) if rest else ''))
            state['backoff_until'] = stamp(epoch(now) + e.retry_after)
            break                         # nothing of this domain is committed
        except (ApiError, KeyError, TypeError) as e:
            errors.append(clean(e))
            continue                      # nothing of this domain is committed
        for c in found:
            dns = sorted({clean(n, 253).lower() for n in (c.get('dns_names') or [])})
            org = issuer_org(c.get('issuer'))
            sha = clean(c.get('cert_sha256') or c.get('tbs_sha256') or '', 64)
            if not baseline and sha not in seen:
                labels = []
                if org not in issuers:
                    labels.append('NEW ISSUER')
                if [n for n in dns if n not in names]:
                    labels.append('NEW NAME')
                new.append({
                    'domain': dom, 'id': str(c['id']), 'sha256': sha, 'names': dns,
                    'issuer': org, 'issuer_name': clean((c.get('issuer') or {}).get('name', ''), 120),
                    'not_before': clean(c.get('not_before', ''), 40),
                    'not_after': clean(c.get('not_after', ''), 40),
                    'labels': labels or ['renewal'], 'found': now,
                })
            seen.add(sha)
            names.update(dns)
            issuers.add(org)
        ds.update(last_id=last, names=sorted(names), issuers=sorted(issuers), checked=now)
        if baseline:
            ds['baseline'] = now
            ds['baseline_count'] = len(found)
        state['domains'][dom] = ds
    state['seen'] = (state['seen'] + [s for s in seen if s not in state['seen']])[-SEEN:]
    return new, errors


def message(new):
    lines = ['CT watch: %d new public TLS certificate%s' % (len(new), '' if len(new) == 1 else 's')]
    for c in new:
        lines.append('')
        lines.append('[%s] %s: %s' % (', '.join(c['labels']), c['domain'], ', '.join(c['names'])))
        lines.append('  %s (%s), %s .. %s' % (c['issuer'], c['issuer_name'], c['not_before'][:10], c['not_after'][:10]))
        lines.append('  https://crt.sh/?sha256=%s' % c['sha256'])
    return '\n'.join(lines) + '\n'


def kuma_summary(new):
    worst = 'NEW ISSUER' if any('NEW ISSUER' in c['labels'] for c in new) else \
            'NEW NAME' if any('NEW NAME' in c['labels'] for c in new) else 'renewal'
    names = sorted({n for c in new for n in c['names']})
    s = '%d new cert(s), %s: %s' % (len(new), worst, ', '.join(names))
    return s if len(s) <= 180 else s[:177] + '...'


def kuma_push(conf, status, msg, timeout=30):
    try:
        with open(os.path.join(conf, 'kuma.url')) as f:
            url = f.read().strip()
    except FileNotFoundError:
        return None                   # not configured: nothing to deliver (deploy.sh says so)
    base = url.split('?', 1)[0]
    q = urllib.parse.urlencode({'status': status, 'msg': msg, 'ping': ''})
    req = urllib.request.Request(base + '?' + q, headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
        return None
    except (OSError, ValueError) as e:
        return 'kuma: %s' % clean(e, 120)


def notify(conf, text, timeout=120):
    hook = os.path.join(conf, 'notify')
    if not os.access(hook, os.X_OK):
        return None                   # not configured: nothing to deliver
    try:
        p = subprocess.run([hook], input=text.encode(), timeout=timeout,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 'notify: %s' % clean(e, 120)
    if p.returncode != 0:
        return 'notify: exit %d %s' % (p.returncode, clean(p.stderr.decode(errors='replace'), 120))
    return None


def read_domains(path):
    out = []
    with open(path) as f:
        for line in f:
            d = line.split('#', 1)[0].strip().lower()
            if d:
                if not re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+', d):
                    raise SystemExit('bad domain in %s: %r' % (path, d))
                out.append(d)
    return out


def run(args, fetch=fetch_api, push=kuma_push, hook=notify, now=None):
    now = now or stamp(time.time())
    domains = read_domains(args.domains)
    path = os.path.join(args.state, 'state.json')
    state = load_state(path)
    wait = state.get('backoff_until')
    if wait and now < wait:          # rate limited: do not spend the next allowance on a sure refusal
        new, errors = [], ['rate limited until %s, not asking' % wait]
    else:
        state.pop('backoff_until', None)
        new, errors = scan(domains, state, fetch, now)
    state['last_run'] = now
    state['last_errors'] = errors
    if not errors:
        state['last_ok'] = now
    state['recent'] = (state['recent'] + new)[-RECENT:]
    save_state(path, state)          # the scan is recorded before alerting; an undelivered alert is kept below

    for d in domains:
        ds = state['domains'].get(d, {})
        if ds.get('baseline') == now:
            print('%s: baseline, %d certificates recorded' % (d, ds.get('baseline_count', 0)))
    for e in errors:
        print('error: %s' % e)
    # An alert that did not get through is kept in the state and sent again every run until it
    # does: the certificates themselves are already recorded and would never be reported again.
    # Kuma stays "down" (no "up") while its alert is pending, and for the run that delivered it.
    kuma = state.pop('kuma_pending', None)
    text = state.pop('notify_pending', None)
    if new:
        sys.stdout.write(message(new))
        kuma = kuma_summary(new) + (' | earlier: ' + kuma if kuma else '')
        kuma = kuma if len(kuma) <= 180 else kuma[:177] + '...'
        text = (text + '\n' if text else '') + message(new)
    if kuma:
        problem = push(args.conf, 'down', kuma)
        if problem:
            print('alert: %s (kept, sent again next run)' % problem)
            state['kuma_pending'] = kuma
    elif not errors:
        problem = push(args.conf, 'up', 'OK, %d domains, nothing new' % len(domains))
        if problem:
            print('alert: %s' % problem)
    if text:
        problem = hook(args.conf, text)
        if problem:
            print('alert: %s (kept, sent again next run)' % problem)
            state['notify_pending'] = text[-20000:]
    save_state(path, state)
    return 1 if errors else 0


def status(args):
    s = load_state(os.path.join(args.state, 'state.json'))
    print('last run: %s, last clean run: %s' % (s.get('last_run', 'never'), s.get('last_ok', 'never')))
    if s.get('backoff_until'):
        print('rate limited, next query after %s' % s['backoff_until'])
    for e in s.get('last_errors') or []:
        print('error: %s' % e)
    print('domains: %s' % ', '.join(sorted(s['domains'])))
    recent = s['recent'][-args.n:]
    if not recent:
        print('no new certificates since the baseline')
    for c in reversed(recent):
        print('%s [%s] %s (%s)' % (c['found'][:16], ', '.join(c['labels']), ', '.join(c['names']), c['issuer']))
    return 0


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description='Watch CT logs for new TLS certificates on our domains.')
    p.add_argument('cmd', choices=['run', 'status'])
    p.add_argument('--domains', default=os.path.join(here, 'domains.txt'))
    p.add_argument('--state', default='/var/lib/ct-watch')
    p.add_argument('--conf', default='/etc/ct-watch')
    p.add_argument('-n', type=int, default=10, help='status: how many certificates')
    args = p.parse_args(argv)
    return run(args) if args.cmd == 'run' else status(args)


if __name__ == '__main__':
    sys.exit(main())
