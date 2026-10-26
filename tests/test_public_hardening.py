import io
import json
import unittest
from email.parser import BytesParser
from types import SimpleNamespace
from unittest.mock import patch

from agentaudit.audit import AuditLog
from agentaudit.clock import FixedClock
from agentaudit.ingest import IngestError
from agentaudit.redact import Redactor
from agentaudit.sample_data import document, span
from agentaudit.store import MemoryStore
from demo import AUDIT_PAGE_ENTRIES, SOURCE_RATE, build_app, visitor_ingest


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


def request(handler, path='/healthz', cookie='', tls=False):
    headers = 'Host: demo.test\r\nContent-Length: 0\r\n'
    if cookie:
        headers += 'Cookie: ' + cookie + '\r\n'
    connection = FakeConnection(('GET ' + path + ' HTTP/1.0\r\n' + headers + '\r\n').encode())
    handler(connection, ('203.0.113.7', 12345), SimpleNamespace(is_tls=tls))
    head, body = bytes(connection.output).split(b'\r\n\r\n', 1)
    status_line, header_lines = head.split(b'\r\n', 1)
    parsed = BytesParser().parsebytes(header_lines + b'\r\n\r\n')
    return int(status_line.split()[1]), body, parsed


class TestPublicHardening(unittest.TestCase):
    def test_trace_limit_is_enforced_before_unbounded_growth_and_cycles_rejected(self):
        clock = FixedClock()
        store = MemoryStore(clock, max_spans_per_trace=1000)
        audit = AuditLog(clock)
        redactor = Redactor(b'key')
        trace_id = 'a' * 32
        for batch in range(2):
            objects = []
            for offset in range(500):
                number = batch * 500 + offset + 1
                sid = f'{number:016x}'
                parent = f'{number - 1:016x}' if number > 1 else ''
                objects.append(span(trace_id, sid, parent, 'node', 'invoke_agent'))
            visitor_ingest(document('visitor', trace_id, objects), redactor, store, audit)
        extra = span(trace_id, f'{1001:016x}', f'{1000:016x}', 'extra', 'invoke_agent')
        with self.assertRaisesRegex(IngestError, 'trace span limit'):
            visitor_ingest(document('visitor', trace_id, [extra]), redactor, store, audit)
        self.assertEqual(len(store.get(trace_id).spans), 1000)

        cyclic_id = 'b' * 32
        cyclic = [
            span(cyclic_id, '1' * 16, '2' * 16, 'one', 'invoke_agent'),
            span(cyclic_id, '2' * 16, '1' * 16, 'two', 'invoke_agent'),
        ]
        with self.assertRaisesRegex(IngestError, 'cyclic'):
            visitor_ingest(document('visitor', cyclic_id, cyclic), redactor, store, audit)

    def test_email_regex_is_skipped_when_at_sign_is_absent(self):
        class ForbiddenPattern:
            def sub(self, *args, **kwargs):
                raise AssertionError('email expression should not run')

        with patch('agentaudit.redact._EMAIL', ForbiddenPattern()):
            output, counts = Redactor(b'key').redact('!' * 8192 + '…')
        self.assertFalse(counts['EMAIL'])
        self.assertTrue(output.endswith('…'))

    def test_audit_page_only_renders_latest_entries(self):
        clock = FixedClock()
        audit = AuditLog(clock)
        for number in range(AUDIT_PAGE_ENTRIES + 25):
            audit.append('unique-actor-' + str(number), 'test', 'target')
        handler = build_app(clock=clock, audit=audit)
        status, body, _ = request(handler, '/audit')
        self.assertEqual(status, 200)
        self.assertNotIn(b'unique-actor-0<', body)
        self.assertIn(('unique-actor-' + str(AUDIT_PAGE_ENTRIES + 24)).encode(), body)
        self.assertEqual(body.count(b'<tr>') - 1, AUDIT_PAGE_ENTRIES)

    def test_source_limit_survives_cookie_rotation(self):
        handler = build_app(clock=FixedClock())
        with patch('demo.time.monotonic', return_value=10.0), patch('demo.time.time', return_value=10.0):
            for _ in range(SOURCE_RATE):
                self.assertEqual(request(handler, cookie='')[0], 200)
            self.assertEqual(request(handler, cookie='')[0], 429)

    def test_tls_cookie_has_secure_attribute(self):
        handler = build_app(clock=FixedClock())
        _, _, headers = request(handler, tls=True)
        cookie = headers['Set-Cookie']
        self.assertIn('Secure', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)


if __name__ == '__main__':
    unittest.main()
