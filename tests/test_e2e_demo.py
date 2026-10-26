import copy
import html
import io
import json
import re
import unittest
from decimal import Decimal
from email.parser import BytesParser
from threading import BoundedSemaphore
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from agentaudit.audit import AuditLog, HmacSigner, verify_export
from agentaudit.clock import FixedClock
from agentaudit.cost import StaticPriceBook, rollup
from agentaudit.redact import Redactor
from agentaudit.sample_data import document, send_sample, span
from agentaudit.sdk import FakeExporter, Tracer
from agentaudit.store import MemoryStore
from agentaudit.vault import FakeVault
from agentaudit.views import BANNER
from demo import DemoServer, MAX_BODY, MAX_TAMPER_BODY, build_app


class FakeConnection:
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()
        self.timeout = None

    def makefile(self, mode, buffering=-1):
        return self.input

    def sendall(self, data):
        self.output.extend(data)

    def settimeout(self, timeout):
        self.timeout = timeout


class TestEndToEndDemo(unittest.TestCase):
    def setUp(self):
        # Fail immediately if this suite accidentally starts using real sockets.
        self.network = patch('socket.socket', side_effect=AssertionError('Network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.clock = FixedClock()
        self.store = MemoryStore(self.clock)
        self.audit = AuditLog(self.clock)
        self.signer = HmacSigner(b'audit-test-key')
        self.vault = FakeVault(max_entries=3)
        self.handler = build_app(clock=self.clock, store=self.store, audit=self.audit,
                                 signer=self.signer, vault=self.vault,
                                 pricebook=StaticPriceBook(), redactor=Redactor(b'redaction-test-key'))
        self.cookie = ''

    def request(self, method, path, body=b'', content_type=None, cookie=None, length=True):
        if isinstance(body, str):
            body = body.encode()
        headers = {'Host': 'demo.test'}
        if length:
            headers['Content-Length'] = str(len(body))
        if content_type:
            headers['Content-Type'] = content_type
        selected = self.cookie if cookie is None else cookie
        if selected:
            headers['Cookie'] = selected
        request = (method + ' ' + path + ' HTTP/1.0\r\n' + ''.join(
            key + ': ' + value + '\r\n' for key, value in headers.items()) + '\r\n').encode() + body
        connection = FakeConnection(request)
        self.handler(connection, ('127.0.0.1', 12345), SimpleNamespace())
        self.assertEqual(connection.timeout, 10)
        head, data = bytes(connection.output).split(b'\r\n\r\n', 1)
        status_line, header_lines = head.split(b'\r\n', 1)
        parsed = BytesParser().parsebytes(header_lines + b'\r\n\r\n')
        if parsed.get('Set-Cookie'):
            self.cookie = parsed['Set-Cookie'].split(';', 1)[0]
        self.assertEqual(int(parsed['Content-Length']), len(data))
        return int(status_line.split()[1]), data, parsed

    def form(self, path, values, **kwargs):
        return self.request('POST', path, urlencode(values),
                            'application/x-www-form-urlencoded', **kwargs)

    def test_full_core_flow_with_fakes(self):
        status, data, headers = self.request('GET', '/traces')
        self.assertEqual(status, 200)
        self.assertEqual(data.count(b"href='/traces/"), 3)
        self.assertIn(BANNER.encode(), data)
        self.assertIn('Content-Security-Policy', headers)
        _, data, _ = self.request('GET', '/traces/' + '2' * 32)
        self.assertIn(b'unparented spans', data)
        self.assertIn(b'<meter', data)

        exporter = FakeExporter()
        tracer = Tracer('Unpublished Person', exporter, self.clock)
        with tracer.span('Unpublished Person at 123 Private Street', {'gen_ai.operation.name': 'invoke_agent'}) as root:
            with tracer.llm('demo-large', 1000, 100):
                pass
            with tracer.span('sub-agent', {'gen_ai.operation.name': 'invoke_agent'}):
                with tracer.span('tool', {'gen_ai.operation.name': 'execute_tool', 'agentaudit.cost_usd': '0.01'}):
                    pass
            with tracer.approval('jürgen\u200b@x.com', 'approved', 'Unpublished Policy'):
                pass
        tracer.flush()
        self.assertEqual(len(exporter.batches), 1)
        status, data, _ = self.request('POST', '/v1/traces', json.dumps(exporter.batches[0]), 'application/json')
        self.assertEqual(status, 200)
        reply = json.loads(data)
        self.assertEqual(reply['accepted'], 5)
        self.assertEqual(reply['redactions']['EMAIL'], 1)
        tid = reply['trace_ids'][0]
        trace = self.store.get(tid)
        self.assertEqual(rollup(trace, StaticPriceBook())[root.obj['spanId']].subtree_cost, Decimal('0.0145'))
        for forbidden in ('Unpublished Person', '123 Private Street', 'jürgen', 'Unpublished Policy'):
            self.assertNotIn(forbidden, repr(self.store._traces))
            self.assertNotIn(forbidden, repr(self.audit.entries()))
        _, data, _ = self.request('GET', '/traces/' + tid)
        self.assertIn(b'Redaction report', data)
        self.assertIn(b'0.014500', data)
        _, data, _ = self.request('GET', '/traces/' + tid + '/replay?step=2')
        self.assertIn(b'Step 2 of 5', data)

        status, _, headers = self.form('/send', {'trace': send_sample()})
        self.assertEqual(status, 303)
        _, data, _ = self.request('GET', headers['Location'])
        self.assertIn(b'Redaction report', data)
        self.assertIn(b'EMAIL', data)
        self.assertNotIn(b'fake.user@example.test', data)
        _, data, _ = self.request('POST', '/audit/verify')
        self.assertIn('✅'.encode(), data)
        _, data, _ = self.request('GET', '/audit/export.json')
        exported = json.loads(data)
        self.assertTrue(verify_export(exported, self.signer).ok)
        damaged = copy.deepcopy(exported)
        damaged['entries'][1]['details']['tampered'] = True
        _, data, _ = self.form('/audit/tamper', {'document': json.dumps(damaged)})
        self.assertIn(('hash_mismatch at entry ' + str(damaged['entries'][1]['seq'])).encode(), data)
        _, data, _ = self.request('GET', '/pack.json')
        pack = json.loads(data)
        integrity = pack['Audit-chain integrity']
        self.assertTrue(integrity['ok'])
        self.assertEqual(integrity['signature'], self.audit.export(self.signer)['signature'])
        self.assertTrue(pack['Human approvals register']['entries'])
        _, data, _ = self.request('GET', '/pack')
        self.assertIn(b'Data inventory', data)
        _, data, _ = self.form('/intent', {'intent': 'Team $49'})
        self.assertIn(b'Anonymous intent recorded', data)
        _, data, _ = self.form('/waitlist', {'email': 'private@example.test'})
        self.assertIn(b'vref_', data)
        self.assertNotIn(b'private@example.test', data)
        self.assertEqual(self.vault.count('email'), 1)
        self.assertFalse(hasattr(self.vault, 'get'))

    def test_tamper_and_download_reupload_after_500_appends(self):
        for _ in range(500):
            self.audit.append('visitor', 'test', 'target')
        _, data, _ = self.request('GET', '/audit/tamper')
        text = html.unescape(re.search(r'<textarea[^>]*>(.*?)</textarea>', data.decode(), re.S).group(1))
        document = json.loads(text)
        self.assertEqual(len(document['entries']), 20)
        self.assertGreater(document['start_seq'], 0)
        self.assertEqual(document['anchor_hash'], document['entries'][0]['prev_hash'])
        self.assertLess(len(urlencode({'document': text}).encode()), MAX_BODY)
        status, data, _ = self.form('/audit/tamper', {'document': text})
        self.assertEqual(status, 200)
        self.assertIn(('hash_mismatch at entry ' + str(document['start_seq'])).encode(), data)
        _, data, _ = self.request('GET', '/audit/export.json')
        exported = json.loads(data)
        self.assertTrue(verify_export(exported, self.signer).ok)
        status, data, _ = self.form('/audit/tamper', {'document': json.dumps(exported)})
        self.assertEqual(status, 200)
        self.assertIn('✅'.encode(), data)
        # A full 500-entry export also fits the separately bounded tamper route.
        full = urlencode({'document': json.dumps(self.audit.export(self.signer), indent=2)})
        self.assertGreater(len(full), MAX_BODY)
        self.assertLess(len(full), MAX_TAMPER_BODY)
        status, data, _ = self.request('POST', '/audit/tamper', full, 'application/x-www-form-urlencoded')
        self.assertEqual(status, 200)
        self.assertIn('✅'.encode(), data)

    def test_intent_and_vault_are_bounded_and_private(self):
        for number in range(12):
            status, _, _ = self.form('/waitlist', {'email': f'contact{number}@example.test',
                                                  'intent': f'Private Name {number}'}, cookie='')
            self.assertEqual(status, 200)
        self.assertEqual(self.vault.count('email'), 3)
        _, data, _ = self.request('GET', '/stats', cookie='')
        self.assertNotIn(b'Private Name', data)
        self.assertNotIn(b'contact', data)
        snapshot = json.loads(html.unescape(re.search(r'<pre>(.*?)</pre>', data.decode(), re.S).group(1)))
        self.assertEqual(set(snapshot['pricing']), {'Solo $19', 'Team $49', 'Enterprise', 'other'})
        self.assertEqual(snapshot['pricing']['other'], 12)
        for number in range(100):
            self.vault.put('kind-' + str(number), 'fake')
        self.assertEqual(self.vault.count('email') + self.vault.count('other'), 3)

    def test_proxy_visitors_have_independent_bounded_rate_buckets(self):
        self.request('GET', '/healthz', cookie='')
        first_cookie = self.cookie
        for _ in range(19):
            self.assertEqual(self.request('GET', '/healthz', cookie=first_cookie)[0], 200)
        self.assertEqual(self.request('GET', '/healthz', cookie=first_cookie)[0], 429)
        self.assertEqual(self.request('GET', '/healthz', cookie='')[0], 200)
        self.assertNotEqual(self.cookie, first_cookie)
        # All fake requests use the same reverse-proxy address.
        self.assertEqual(self.request('GET', '/healthz')[0], 200)

    def test_contract_and_unicode_regressions(self):
        redactor = Redactor(b'key')
        clean, counts = redactor.redact('jürgen@x.com')
        obscured, obscured_counts = redactor.redact('jür\u200bgen@x\u200d.com')
        self.assertEqual(clean, obscured)
        self.assertEqual(counts, obscured_counts)
        self.assertEqual(counts['EMAIL'], 1)
        self.assertNotIn('jü', clean)
        self.assertEqual(self.request('POST', '/v1/traces', b'{}', 'application/json', length=False)[0], 411)
        self.assertEqual(self.request('POST', '/v1/traces', b'x' * (MAX_BODY + 1), 'application/json')[0], 413)
        self.assertEqual(self.request('POST', '/v1/traces', b'{}', 'text/plain')[0], 400)
        status, data, _ = self.request('POST', '/v1/traces', b'{secret@example.test', 'application/json')
        self.assertEqual(status, 400)
        self.assertNotIn(b'secret', data)
        self.assertEqual(self.request('POST', '/audit/tamper', b'x' * (MAX_TAMPER_BODY + 1))[0], 413)

    def test_orphan_is_reparented_without_double_counting(self):
        tid = 'a' * 32
        child = span(tid, 'b' * 16, 'c' * 16, 'child', 'execute_tool')
        parent = span(tid, 'c' * 16, '', 'parent', 'invoke_agent')
        for item in (child, parent):
            status, _, _ = self.request('POST', '/v1/traces', json.dumps(document('visitor', tid, [item])), 'application/json')
            self.assertEqual(status, 200)
            trace = self.store.get(tid)
            self.assertEqual(trace.spans['b' * 16].orphan, item is child)
        self.assertEqual(len(rollup(trace, StaticPriceBook())), 2)

    def test_connection_cap_rejects_and_releases_slots(self):
        server = DemoServer.__new__(DemoServer)
        server.slots = BoundedSemaphore(1)
        server.shutdown_request = Mock()
        request = object()
        server.slots.acquire()
        server.process_request(request, ('127.0.0.1', 1))
        server.shutdown_request.assert_called_once_with(request)
        server.slots.release()
        with patch('http.server.ThreadingHTTPServer.process_request', side_effect=RuntimeError('thread failure')):
            with self.assertRaises(RuntimeError):
                server.process_request(request, ('127.0.0.1', 1))
        self.assertTrue(server.slots.acquire(blocking=False))
        with patch('http.server.ThreadingHTTPServer.process_request_thread'):
            server.process_request_thread(request, ('127.0.0.1', 1))
        self.assertTrue(server.slots.acquire(blocking=False))
        self.assertTrue(DemoServer.daemon_threads)


if __name__ == '__main__':
    unittest.main()
