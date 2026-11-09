#!/usr/bin/env python3
"""Tests for ct_watch.py on recorded-shape API answers, no network.  python3 test_ct_watch.py"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ct_watch  # noqa: E402

LE = {'friendly_name': "Let's Encrypt", 'name': "C=US, O=Let's Encrypt, CN=YR1"}
ZS = {'friendly_name': 'ZeroSSL', 'name': 'C=AT, O=ZeroSSL, CN=ZeroSSL ECC DV SSL CA 2'}
EVIL = {'friendly_name': 'Some Other CA', 'name': 'C=XX, O=Other, CN=Other CA'}


def cert(i, names, issuer=LE):
    return {'id': str(i), 'cert_sha256': '%064x' % i, 'tbs_sha256': 'ff' * 32, 'dns_names': names,
            'issuer': issuer, 'not_before': '2026-11-09T00:00:00Z', 'not_after': '2027-02-07T00:00:00Z',
            'revoked': False}


class FakeApi:
    """Issuances per domain, served after an id in pages of `page`, like the real API."""
    def __init__(self, page=100):
        self.data, self.page, self.fail, self.limit, self.calls = {}, page, set(), set(), []

    def add(self, domain, c):
        self.data.setdefault(domain, []).append(c)

    def __call__(self, domain, after):
        self.calls.append((domain, after))
        if domain in self.fail:
            raise ct_watch.ApiError('%s: HTTP 500' % domain)
        if domain in self.limit:
            raise ct_watch.RateLimited('%s: HTTP 429' % domain, 329)
        rows = [c for c in self.data.get(domain, []) if after is None or int(c['id']) > int(after)]
        return rows[:self.page]


class Alerts:
    """Records what was sent; `kuma_down` / `hook_down` make that channel fail (the call is still recorded)."""
    def __init__(self, kuma_down=False, hook_down=False):
        self.pushes, self.texts = [], []
        self.kuma_down, self.hook_down = kuma_down, hook_down

    def push(self, conf, status, msg):
        self.pushes.append((status, msg))
        return 'kuma: HTTP Error 502: Bad Gateway' if self.kuma_down else None

    def hook(self, conf, text):
        self.texts.append(text)
        return 'notify: exit 1' if self.hook_down else None


class T(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.domains = os.path.join(self.dir, 'domains.txt')
        with open(self.domains, 'w') as f:
            f.write('# watched\nonchato.com\nence.do  # devices\n')
        self.args = SimpleNamespace(domains=self.domains, state=self.dir, conf=self.dir, n=10)
        self.api = FakeApi()
        self.api.add('onchato.com', cert(10, ['onchato.com']))
        self.api.add('onchato.com', cert(11, ['app.onchato.com', 'bs1.onchato.com']))
        self.api.add('ence.do', cert(20, ['ip10.ence.do'], ZS))
        self.out = []

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_once(self, now='2026-11-09T10:00:00Z', **down):
        a = Alerts(**down)
        rc = ct_watch.run(self.args, fetch=self.api, push=a.push, hook=a.hook, now=now)
        return rc, a

    def state(self):
        with open(os.path.join(self.dir, 'state.json')) as f:
            return json.load(f)

    def test_baseline_reports_nothing(self):
        rc, a = self.run_once()
        self.assertEqual(rc, 0)
        self.assertEqual(a.texts, [])
        self.assertEqual(a.pushes[0][0], 'up')
        s = self.state()
        self.assertEqual(s['domains']['onchato.com']['last_id'], '11')
        self.assertEqual(s['domains']['ence.do']['issuers'], ['ZeroSSL'])

    def test_nothing_new_is_up(self):
        self.run_once()
        rc, a = self.run_once()
        self.assertEqual((rc, a.texts, [p[0] for p in a.pushes]), (0, [], ['up']))
        self.assertIn(('onchato.com', '11'), self.api.calls)      # asks only after the last id

    def test_renewal(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['bs1.onchato.com', 'app.onchato.com']))
        rc, a = self.run_once()
        self.assertEqual(a.pushes[0][0], 'down')
        self.assertIn('[renewal] onchato.com: app.onchato.com, bs1.onchato.com', a.texts[0])
        self.assertIn('https://crt.sh/?sha256=%064x' % 12, a.texts[0])
        self.assertIn('renewal', a.pushes[0][1])

    def test_new_name(self):
        self.run_once()
        self.api.add('ence.do', cert(21, ['cctest1.ence.do'], ZS))
        rc, a = self.run_once()
        self.assertIn('[NEW NAME] ence.do: cctest1.ence.do', a.texts[0])
        self.assertIn('NEW NAME', a.pushes[0][1])

    def test_new_issuer(self):
        self.run_once()
        self.api.add('onchato.com', cert(13, ['onchato.com'], EVIL))
        rc, a = self.run_once()
        self.assertIn('[NEW ISSUER] onchato.com: onchato.com', a.texts[0])
        self.assertIn('NEW ISSUER', a.pushes[0][1])

    def test_one_message_per_run(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        self.api.add('ence.do', cert(21, ['x.ence.do'], ZS))
        rc, a = self.run_once()
        self.assertEqual(len(a.texts), 1)
        self.assertEqual(len(a.pushes), 1)
        self.assertTrue(a.texts[0].startswith('CT watch: 2 new public TLS certificates'))

    def test_reported_once(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        self.run_once()
        rc, a = self.run_once()
        self.assertEqual((a.texts, a.pushes[0][0]), ([], 'up'))

    def test_pages(self):
        self.api.page = 1
        self.run_once()
        self.api.add('onchato.com', cert(12, ['a.onchato.com']))
        self.api.add('onchato.com', cert(13, ['b.onchato.com']))
        rc, a = self.run_once()
        self.assertIn('a.onchato.com', a.texts[0])
        self.assertIn('b.onchato.com', a.texts[0])
        self.assertEqual(self.state()['domains']['onchato.com']['last_id'], '13')

    def test_one_cert_two_domains_reported_once(self):
        self.run_once()
        c = cert(30, ['new.onchato.com', 'new.ence.do'])
        self.api.add('onchato.com', c)
        self.api.add('ence.do', c)
        rc, a = self.run_once()
        self.assertEqual(a.texts[0].count('https://crt.sh/'), 1)

    def test_api_error_keeps_state_and_stays_silent(self):
        self.run_once()
        self.api.add('ence.do', cert(21, ['y.ence.do'], ZS))
        self.api.fail.add('ence.do')
        rc, a = self.run_once()
        self.assertEqual((rc, a.texts, a.pushes), (1, [], []))     # no "up": Kuma's heartbeat runs out
        self.assertEqual(self.state()['domains']['ence.do']['last_id'], '20')
        self.api.fail.clear()
        rc, a = self.run_once()
        self.assertIn('y.ence.do', a.texts[0])                     # reported on the next good run

    def test_error_during_baseline_keeps_it_a_baseline(self):
        self.api.fail.add('ence.do')
        rc, a = self.run_once()
        self.assertEqual(rc, 1)
        self.assertNotIn('ence.do', self.state()['domains'])
        self.api.fail.clear()
        rc, a = self.run_once()                                    # the real baseline: silent
        self.assertEqual((rc, a.texts, a.pushes[0][0]), (0, [], 'up'))

    def test_error_in_one_domain_still_reports_the_other(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['z.onchato.com']))
        self.api.fail.add('ence.do')
        rc, a = self.run_once()
        self.assertEqual(rc, 1)
        self.assertIn('z.onchato.com', a.texts[0])
        self.assertEqual(a.pushes[0][0], 'down')

    def test_rate_limit_stops_the_run(self):
        self.run_once()
        self.api.limit.add('onchato.com')
        self.api.calls.clear()
        rc, a = self.run_once('2026-11-09T11:00:00Z')
        self.assertEqual((rc, a.pushes), (1, []))
        self.assertEqual([c[0] for c in self.api.calls], ['onchato.com'])    # ence.do not asked
        s = self.state()
        self.assertEqual(s['backoff_until'], '2026-11-09T11:05:29Z')
        self.assertIn('not asked: ence.do', s['last_errors'][0])

    def test_backoff_asks_nothing_until_it_ends(self):
        self.run_once()
        self.api.limit.add('onchato.com')
        self.run_once('2026-11-09T11:00:00Z')
        self.api.limit.clear()
        self.api.add('ence.do', cert(21, ['w.ence.do'], ZS))
        self.api.calls.clear()
        rc, a = self.run_once('2026-11-09T11:05:00Z')                       # before the end
        self.assertEqual((rc, self.api.calls, a.pushes, a.texts), (1, [], [], []))
        rc, a = self.run_once('2026-11-09T11:05:30Z')                       # after it
        self.assertEqual(rc, 0)
        self.assertIn('w.ence.do', a.texts[0])
        self.assertNotIn('backoff_until', self.state())

    def test_longest_unchecked_domain_first(self):
        self.run_once()
        self.api.limit.add('ence.do')
        self.run_once('2026-11-09T11:00:00Z')        # onchato.com checked, ence.do limited
        self.api.limit.clear()
        self.api.calls.clear()
        self.run_once('2026-11-09T12:00:00Z')
        self.assertEqual([c[0] for c in self.api.calls][0], 'ence.do')

    def test_retry_seconds(self):
        self.assertEqual(ct_watch.retry_seconds('329'), 329)
        self.assertEqual(ct_watch.retry_seconds('5'), 60)
        self.assertEqual(ct_watch.retry_seconds('99999'), 7200)
        self.assertEqual(ct_watch.retry_seconds(None), 600)
        self.assertEqual(ct_watch.retry_seconds('Wed, 21 Oct 2026 07:28:00 GMT'), 600)

    def test_kuma_failure_is_sent_again_until_it_gets_through(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        rc, a = self.run_once('2026-11-09T11:00:00Z', kuma_down=True)
        self.assertEqual(a.pushes[0][0], 'down')
        self.assertEqual(len(a.texts), 1)                          # the bot got it
        rc, a = self.run_once('2026-11-09T12:00:00Z', kuma_down=True)
        self.assertEqual([p[0] for p in a.pushes], ['down'])       # again, not "up"
        self.assertIn('app.onchato.com', a.pushes[0][1])
        self.assertEqual(a.texts, [])                              # the bot is not told twice
        rc, a = self.run_once('2026-11-09T13:00:00Z')
        self.assertEqual([p[0] for p in a.pushes], ['down'])       # delivered now
        rc, a = self.run_once('2026-11-09T14:00:00Z')
        self.assertEqual([p[0] for p in a.pushes], ['up'])         # and back to normal

    def test_pending_kuma_alert_joins_a_new_one(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        self.run_once('2026-11-09T11:00:00Z', kuma_down=True)
        self.api.add('ence.do', cert(21, ['n.ence.do'], ZS))
        rc, a = self.run_once('2026-11-09T12:00:00Z')
        self.assertIn('n.ence.do', a.pushes[0][1])
        self.assertIn('earlier: 1 new cert(s), renewal: app.onchato.com', a.pushes[0][1])

    def test_hook_failure_is_sent_again(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        self.run_once('2026-11-09T11:00:00Z', hook_down=True)
        rc, a = self.run_once('2026-11-09T12:00:00Z')
        self.assertEqual(len(a.texts), 1)
        self.assertIn('app.onchato.com', a.texts[0])
        rc, a = self.run_once('2026-11-09T13:00:00Z')
        self.assertEqual(a.texts, [])

    def test_pending_alert_sent_during_backoff(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['app.onchato.com']))
        self.api.limit.add('ence.do')                              # onchato.com is read, then 429
        self.run_once('2026-11-09T11:00:00Z', kuma_down=True)
        self.api.calls.clear()
        rc, a = self.run_once('2026-11-09T11:02:00Z')              # still in the backoff
        self.assertEqual(self.api.calls, [])
        self.assertEqual([p[0] for p in a.pushes], ['down'])
        self.assertIn('app.onchato.com', a.pushes[0][1])

    def test_baseline_of_a_new_domain_later(self):
        self.run_once()
        with open(self.domains, 'a') as f:
            f.write('rkv.pl\n')
        self.api.add('rkv.pl', cert(40, ['rkv.pl']))
        rc, a = self.run_once()
        self.assertEqual((a.texts, a.pushes[0][0]), ([], 'up'))

    def test_control_characters_cleaned(self):
        self.run_once()
        self.api.add('onchato.com', cert(12, ['evil\n.onchato.com\x1b[31m'], dict(EVIL, name='a\rb')))
        rc, a = self.run_once()
        body = a.texts[0]
        self.assertNotIn('\x1b', body)
        self.assertNotIn('\r', body)
        self.assertIn('evil?.onchato.com?[31m', body)

    def test_bad_domain_file(self):
        with open(self.domains, 'w') as f:
            f.write('onchato.com/x\n')
        with self.assertRaises(SystemExit):
            self.run_once()

    def test_status(self):
        self.run_once()
        self.api.add('ence.do', cert(21, ['q.ence.do'], ZS))
        self.run_once()
        out = []
        orig = ct_watch.print
        try:
            ct_watch.print = lambda *x: out.append(' '.join(map(str, x)))
            ct_watch.status(self.args)
        finally:
            ct_watch.print = orig
        self.assertIn('[NEW NAME] q.ence.do (ZeroSSL)', '\n'.join(out))


if __name__ == '__main__':
    ct_watch.print = print
    unittest.main(verbosity=1)
