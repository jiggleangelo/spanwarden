import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import time
from collections import OrderedDict
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore, Lock
from urllib.parse import parse_qs, unquote, urlparse

from agentaudit.audit import AuditLog, HmacSigner, verify_export
from agentaudit.clock import SystemClock
from agentaudit.cost import StaticPriceBook
from agentaudit.ingest import IngestError, ingest, parse
from agentaudit.pack import build_dpo_pack
from agentaudit.redact import Redactor
from agentaudit.sample_data import samples, send_sample
from agentaudit.store import MemoryStore
from agentaudit.vault import FakeVault
from agentaudit.views import e, home, pack_html, page, trace_list, trace_page

MAX_BODY = 65536
MAX_TAMPER_BODY = 2 * 1024 * 1024
MAX_COUNTER = 2**31 - 1
MAX_SPANS_PER_TRACE = 1000
AUDIT_PAGE_ENTRIES = 100
COOKIE_RATE = 20
SOURCE_RATE = 100
INTENTS = ('Solo $19', 'Team $49', 'Enterprise', 'other')
EMAIL = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
TOKEN = re.compile(r'\[(?:EMAIL|NRIC|PHONE_SG|IPV4|CARD|CARD_CANDIDATE)#[0-9a-f]{12}\]')
CSP = "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'"
STYLE = ("body{font:16px system-ui;margin:0;color:#172033;background:#f6f8fb}main,nav,footer{max-width:1100px;margin:auto;padding:1rem}.banner{padding:.7rem;text-align:center;background:#ffe9a8}.span,section,table,form{background:white;margin:.5rem 0;padding:.8rem;border:1px solid #dbe1ea;border-radius:6px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.5rem;border-bottom:1px solid #ddd}textarea{box-sizing:border-box;width:100%}pre{white-space:pre-wrap;overflow-wrap:anywhere}.orphan{border-left:5px solid #e88b00}.error{background:#fff0f0}.notice{color:#285}.toggle{border:0;background:transparent;cursor:pointer}a{color:#0759b7}footer{font-size:.85rem;color:#586273}meter{width:12rem}" + ''.join(f'.depth-{n}{{margin-left:{n * 24}px}}' for n in range(21))).encode()
SCRIPT = b"document.addEventListener('click',function(e){var b=e.target.closest('.toggle');if(!b)return;var p=b.parentElement.querySelector('pre');p.hidden=!p.hidden;b.textContent=p.hidden?'\\u25b6':'\\u25bc';});"


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, max_connections=32):
        if max_connections < 1:
            raise ValueError('max_connections must be positive')
        self.slots = BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


def export_window(audit, signer, limit=20):
    document = audit.export(signer)
    entries = document['entries'][-limit:]
    if entries:
        document['start_seq'] = entries[0]['seq']
        document['anchor_hash'] = entries[0]['prev_hash']
    document['entries'] = entries
    document['signature'] = signer.sign(document['head_hash'], len(entries), document['version'], document['key_id'], document['start_seq'], document['anchor_hash'])
    return document


def safe_text(value):
    return 'Visitor text omitted ' + ' '.join(TOKEN.findall(str(value)))


def _validate_acyclic(parents):
    finished = set()
    for start in parents:
        if start in finished:
            continue
        path = set()
        current = start
        while current in parents and current not in finished:
            if current in path:
                raise IngestError('cyclic span tree')
            path.add(current)
            current = parents[current]
        finished.update(path)


def visitor_ingest(payload, redactor, store, audit):
    spans, services, counts = parse(payload, redactor)
    grouped = {}
    models = {'demo-large', 'demo-small'}
    numeric = {'gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens', 'llm.token_count.prompt', 'llm.token_count.completion', 'agentaudit.cost_usd', 'agentaudit.time_clamped'}
    for span in spans:
        span.name = str(span.kind).title() + ': ' + safe_text(span.name)
        span.model = span.model if span.model in models else 'unknown-model' if span.model else None
        span.tool_name = 'visitor-tool' if span.tool_name else None
        attributes = {}
        for index, (key, value) in enumerate(span.attributes.items()):
            if key in numeric:
                attributes[key] = value if isinstance(value, (int, float, bool)) else safe_text(value)
            elif key == 'agentaudit.approval.decision':
                attributes[key] = value if value in ('approved', 'rejected') else 'rejected'
            elif key in ('agentaudit.approval.approver', 'agentaudit.approval.policy'):
                attributes[key] = safe_text(value)
            else:
                attributes['visitor.field.' + str(index)] = safe_text(value)
        span.attributes = attributes
        span.events = [{'name': 'Visitor event', 'attributes': {'visitor.field.' + str(index): safe_text(value) for index, value in enumerate(event['attributes'].values())}} for event in span.events]
        grouped.setdefault(span.trace_id, []).append(span)

    for trace_id, group in grouped.items():
        previous = store.get(trace_id)
        previous_spans = previous.spans if previous else {}
        limit = min(MAX_SPANS_PER_TRACE, getattr(store, 'max_spans_per_trace', MAX_SPANS_PER_TRACE))
        if len(previous_spans) + len(group) > limit:
            raise IngestError('trace span limit exceeded')
        parents = {sid: item.parent_id for sid, item in previous_spans.items()}
        parents.update({item.span_id: item.parent_id for item in group})
        _validate_acyclic(parents)

    for trace_id, group in grouped.items():
        report = counts.by_trace.get(trace_id, {})
        store.put_spans(group, 'visitor-agent', report)
        audit.append('demo-visitor', 'trace.ingested', trace_id, details={'spans': len(group), 'redactions': sum(report.values())})
        for span in group:
            if span.kind == 'approval':
                attrs = span.attributes
                audit.append(attrs.get('agentaudit.approval.approver', 'unknown'), 'step.' + attrs['agentaudit.approval.decision'], trace_id + ':' + span.span_id, attrs.get('agentaudit.approval.policy', 'n/a'), {'assertion': 'caller-supplied; unverified'})
    return len(spans), list(grouped), dict(counts)


def build_app(clock=None, pricebook=None, vault=None, store=None, redactor=None, audit=None, signer=None):
    clock = clock or SystemClock()
    pricebook = pricebook or StaticPriceBook()
    vault = vault or FakeVault()
    store = store or MemoryStore(clock, max_spans_per_trace=MAX_SPANS_PER_TRACE)
    redactor = redactor or Redactor(os.environ.get('REDACTION_KEY', '').encode() or secrets.token_bytes(32))
    audit = audit or AuditLog(clock)
    signer = signer or HmacSigner(os.environ.get('AUDIT_SIGNING_KEY', '').encode() or secrets.token_bytes(32))
    for sample in samples():
        ingest(sample, redactor, store, audit, True)
    stats = {name: 0 for name in ('tour_1', 'tour_2', 'tour_3', 'tour_4', 'tour_5', 'completed')}
    stats['pricing'] = dict.fromkeys(INTENTS, 0)
    config = {'residency_region': 'local-demo (production target: Singapore region)', 'retention': 'process lifetime with bounded audit, trace and vault storage'}
    rate = OrderedDict()
    source_rate = OrderedDict()
    rate_lock, stats_lock = Lock(), Lock()
    cookie_key = secrets.token_bytes(32)

    def bump(name):
        with stats_lock:
            stats[name] = min(MAX_COUNTER, stats[name] + 1)

    def record_intent(form):
        intent = form.get('intent', ['other'])[0]
        intent = intent if intent in INTENTS else 'other'
        with stats_lock:
            stats['pricing'][intent] = min(MAX_COUNTER, stats['pricing'][intent] + 1)

    class Handler(BaseHTTPRequestHandler):
        timeout = 10

        def log_message(self, *args):
            pass

        def _headers(self, status, ctype, length, extra=None):
            self.send_response(status)
            for key, value in {'Content-Type': ctype, 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'Content-Length': str(length)}.items():
                self.send_header(key, value)
            if getattr(self, 'new_cookie', None):
                flags = '; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600'
                if isinstance(getattr(self, 'connection', None), ssl.SSLSocket) or getattr(self.server, 'is_tls', False):
                    flags += '; Secure'
                self.send_header('Set-Cookie', 'aa_demo=' + self.new_cookie + flags)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()

        def send_bytes(self, status, data, ctype='text/html; charset=utf-8', extra=None):
            data = data.encode() if isinstance(data, str) else data
            self._headers(status, ctype, len(data), extra)
            self.wfile.write(data)

        def send_json(self, status, value):
            self.send_bytes(status, json.dumps(value, separators=(',', ':')), 'application/json')

        def html(self, status, title, body):
            self.send_bytes(status, page(title, body))

        def error_page(self, status, message):
            self.html(status, 'Error', '<p>' + e(message) + '</p>')

        def body(self, json_error=False):
            def fail(status, message):
                self.close_connection = True
                if json_error:
                    self.send_json(status, {'error': message})
                else:
                    self.error_page(status, message)
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
                fail(400, 'Invalid request framing')
                return None
            raw = self.headers.get('Content-Length')
            if raw is None:
                fail(411, 'Content-Length required')
                return None
            if not re.fullmatch(r'[0-9]{1,10}', raw):
                fail(400, 'Invalid request')
                return None
            length = int(raw)
            limit = MAX_TAMPER_BODY if urlparse(self.path).path == '/audit/tamper' else MAX_BODY
            if length > limit:
                fail(413, 'Request body exceeds route limit')
                return None
            try:
                data = self.rfile.read(length)
            except TimeoutError:
                fail(408, 'Request timeout')
                return None
            if len(data) != length:
                fail(400, 'Invalid request')
                return None
            return data

        def allowed(self):
            self.new_cookie = None
            token = ''
            try:
                cookies = SimpleCookie()
                cookies.load(self.headers.get('Cookie', '')[:4096])
                token = cookies['aa_demo'].value if 'aa_demo' in cookies else ''
                identity, issued, signature = token.split('.')
                body = identity + '.' + issued
                valid = (re.fullmatch(r'[0-9a-f]{32}', identity) is not None and 0 <= time.time() - int(issued) <= 3600 and hmac.compare_digest(signature, hmac.new(cookie_key, body.encode(), hashlib.sha256).hexdigest()))
            except (ValueError, KeyError):
                valid = False
            if not valid:
                identity = secrets.token_hex(16)
                body = identity + '.' + str(int(time.time()))
                self.new_cookie = body + '.' + hmac.new(cookie_key, body.encode(), hashlib.sha256).hexdigest()

            source = str(self.client_address[0]) if self.client_address else 'unknown'
            source_id = hmac.new(cookie_key, ('source\0' + source).encode(), hashlib.sha256).digest()[:16]
            now = time.monotonic()
            with rate_lock:
                start, count = rate.pop(identity, (now, 0))
                if now - start >= 1:
                    start, count = now, 0
                cookie_allowed = count < COOKIE_RATE
                rate[identity] = (start, min(COOKIE_RATE, count + 1))
                if len(rate) > 1024:
                    rate.popitem(last=False)

                source_start, source_count = source_rate.pop(source_id, (now, 0))
                if now - source_start >= 1:
                    source_start, source_count = now, 0
                source_allowed = source_count < SOURCE_RATE
                source_rate[source_id] = (source_start, min(SOURCE_RATE, source_count + 1))
                if len(source_rate) > 1024:
                    source_rate.popitem(last=False)
            return cookie_allowed and source_allowed

        def form(self, raw):
            return parse_qs(raw.decode('utf-8'), keep_blank_values=True, max_num_fields=20)

        def redirect(self, location):
            self.send_bytes(303, b'', extra={'Location': location})

        def dispatch(self, operation):
            try:
                if not self.allowed():
                    if urlparse(self.path).path == '/v1/traces':
                        self.send_json(429, {'error': 'Too many requests'})
                    else:
                        self.error_page(429, 'Too many requests')
                    return
                operation()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True
            except Exception:
                if urlparse(self.path).path == '/v1/traces':
                    self.send_json(400, {'error': 'Invalid trace document'})
                else:
                    self.error_page(400, 'Invalid request')

        def do_GET(self):
            self.dispatch(self._get)

        def do_POST(self):
            self.dispatch(self._post)

        def _get(self):
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            if path == '/healthz':
                self.send_bytes(200, 'ok', 'text/plain; charset=utf-8')
            elif path == '/static/style.css':
                self.send_bytes(200, STYLE, 'text/css; charset=utf-8')
            elif path == '/static/app.js':
                self.send_bytes(200, SCRIPT, 'text/javascript; charset=utf-8')
            elif path == '/':
                self.send_bytes(200, home())
            elif path == '/traces':
                bump('tour_1')
                self.send_bytes(200, trace_list(store.list(), pricebook))
            elif path.startswith('/traces/'):
                bits = path.strip('/').split('/')
                trace = store.get(bits[1])
                if not trace:
                    self.error_page(404, 'Trace not found')
                    return
                bump('tour_2')
                if len(bits) == 3 and bits[2] == 'replay':
                    ordered = sorted(trace.spans.values(), key=lambda span: (span.start_ns, span.span_id))
                    if not ordered:
                        self.error_page(404, 'Trace is empty')
                        return
                    try:
                        number = int(parse_qs(parsed.query).get('step', ['1'])[0])
                    except ValueError:
                        number = 1
                    number = max(1, min(len(ordered), number))
                    span = ordered[number - 1]
                    links = (f"<a href='?step={number - 1}'>Prev</a> " if number > 1 else '') + (f"<a href='?step={number + 1}'>Next</a>" if number < len(ordered) else '')
                    self.html(200, 'Read-only replay', f'<p>Step {number} of {len(ordered)}. No agent or tool is executed.</p><h2>{e(span.name)}</h2><pre>{e(json.dumps(span.attributes))}</pre><p>{links}</p>')
                elif len(bits) == 2:
                    self.send_bytes(200, trace_page(trace, pricebook))
                else:
                    self.error_page(404, 'Not found')
            elif path == '/send':
                self.html(200, 'Send trace', '<p>Public demo: visitor prose is omitted before storage. Structural fields and redaction tokens remain visible.</p><form method=post><textarea name=trace rows=24>' + e(send_sample()) + '</textarea><button>Send fake trace</button></form>')
            elif path == '/audit':
                bump('tour_4')
                rows = ''.join(f'<tr><td>{item.seq}</td><td>{e(item.ts)}</td><td>{e(item.actor)}</td><td>{e(item.action)}</td><td>{e(item.target)}</td><td>{e(item.authority)}</td></tr>' for item in audit.tail(AUDIT_PAGE_ENTRIES))
                self.html(200, 'Audit', f'<p>Showing the latest {AUDIT_PAGE_ENTRIES} retained entries. Actors and authorities are unauthenticated caller assertions.</p><form method=post action=/audit/verify><button>Verify live chain</button></form><p><a href=/audit/export.json>Download signed last-20-entry window</a> · <a href=/audit/tamper>Tamper test</a></p><table><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Authority</th></tr>' + rows + '</table>')
            elif path == '/audit/export.json':
                self.send_json(200, export_window(audit, signer))
            elif path == '/audit/tamper':
                document = export_window(audit, signer)
                if document['entries']:
                    document['entries'][0]['details']['altered'] = True
                self.html(200, 'Tamper test', '<p>This is a signed window of the last 20 entries with its original sequence and anchor. The first entry has been altered after signing. Signature and tail failures are document-level.</p><form method=post><textarea name=document rows=24>' + e(json.dumps(document, indent=2)) + '</textarea><button>Verify altered export</button></form>')
            elif path in ('/pack', '/pack.json'):
                bump('tour_5')
                bump('completed')
                pack = build_dpo_pack(store, audit, signer, config, clock)
                self.send_json(200, pack) if path.endswith('.json') else self.send_bytes(200, pack_html(pack))
            elif path == '/pricing':
                options = ''.join('<option>' + e(intent) + '</option>' for intent in INTENTS[:3])
                self.html(200, 'Pricing', '<p>Illustrative only; nothing is charged. Answer anonymously; contact details are optional and separate.</p><form method=post action=/intent><label>Which plan would you consider? <select name=intent>' + options + '</select></label><button>Record intent</button></form><form method=post action=/waitlist><label>Optional waitlist email <input name=email type=email required maxlength=254></label><button>Join waitlist</button></form>')
            elif path == '/stats':
                with stats_lock:
                    snapshot = json.loads(json.dumps(stats))
                self.html(200, 'Stats', '<pre>' + e(json.dumps(snapshot, indent=2)) + '</pre>')
            else:
                self.error_page(404, 'Not found')

        def _post(self):
            path = unquote(urlparse(self.path).path)
            raw = self.body(path == '/v1/traces')
            if raw is None:
                return
            if path == '/v1/traces':
                if self.headers.get_content_type() != 'application/json':
                    self.send_json(400, {'error': 'Content-Type must be application/json'})
                    return
                accepted, trace_ids, counts = visitor_ingest(json.loads(raw), redactor, store, audit)
                self.send_json(200, {'accepted': accepted, 'trace_ids': trace_ids, 'redactions': counts})
            elif path == '/send':
                form = self.form(raw)
                accepted, trace_ids, counts = visitor_ingest(json.loads(form['trace'][0]), redactor, store, audit)
                bump('tour_3')
                self.redirect('/traces/' + trace_ids[0] if trace_ids else '/traces')
            elif path == '/audit/verify':
                result = verify_export(audit.export(signer), signer)
                audit.append('demo-visitor', 'audit.verified', 'live-chain', details={'ok': result.ok})
                self.html(200, 'Audit verification', f"<p>{'✅' if result.ok else '❌'} {e(result.reason)}</p><p><a href=/audit>Back to audit</a></p>")
            elif path == '/audit/tamper':
                document = json.loads(self.form(raw)['document'][0])
                result = verify_export(document, signer)
                audit.append('demo-visitor', 'audit.tamper_tested', 'submitted-export', details={'ok': result.ok, 'reason': result.reason})
                location = 'document-level' if result.first_bad_seq is None else 'entry ' + str(result.first_bad_seq)
                self.html(200, 'Tamper result', f"<p>{'✅' if result.ok else '❌'} {e(result.reason)} at {e(location)}</p><p><a href=/audit/tamper>Try again</a></p>")
            elif path == '/intent':
                record_intent(self.form(raw))
                self.html(200, 'Pricing intent', '<p>Anonymous intent recorded. Nothing is charged.</p>')
            elif path == '/waitlist':
                form = self.form(raw)
                email = form.get('email', [''])[0]
                if len(email) > 254 or not EMAIL.fullmatch(email):
                    raise ValueError('Invalid email')
                reference = vault.put('email', email)
                if 'intent' in form:
                    record_intent(form)
                self.html(200, 'Waitlist', '<p>Stored in the bounded write-only vault as <code>' + e(reference) + '</code>. The address is not displayed or linked to pricing counters.</p>')
            else:
                self.error_page(404, 'Not found')

    return Handler


def main():
    server = DemoServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), build_app())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
