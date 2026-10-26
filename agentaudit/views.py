import html
import json
from decimal import Decimal

from .cost import money, rollup

BANNER = 'Demo operated by AI agents. Made-up data. Do not enter real personal data. Nothing is charged.'


def e(value):
    return html.escape(str(value), quote=True)


def page(title, body):
    return "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'><title>" + e(title) + "</title><link rel=stylesheet href=/static/style.css><script defer src=/static/app.js></script></head><body><div class=banner>" + BANNER + '</div><nav><a href=/>Tour</a> <a href=/traces>Traces</a> <a href=/send>Send trace</a> <a href=/audit>Audit</a> <a href=/pack>DPO pack</a> <a href=/pricing>Pricing</a> <a href=/stats>Stats</a></nav><main><h1>' + e(title) + '</h1>' + body + '</main><footer>Evidence to support a DPO review—not legal advice. State and unauthenticated identities are demo-only and are lost on restart.</footer></body></html>'


def home():
    return page('AgentAudit guided demo', '<ol><li><a href=/traces>Open a trace</a></li><li><a href=/send>Send fake PII</a></li><li><a href=/audit>Verify the audit log</a></li><li><a href=/audit/tamper>Run the tamper test</a></li><li><a href=/pack>Open the DPO evidence pack</a></li></ol><p>Designed to finish in under three minutes.</p>')


def trace_list(traces, pricebook):
    rows = []
    for trace in traces:
        values = rollup(trace, pricebook)
        roots = [span for span in trace.spans.values() if not span.parent_id or span.parent_id not in trace.spans]
        total = sum((values[span.span_id].subtree_cost for span in roots), start=Decimal('0'))
        badges = []
        if any(span.orphan for span in trace.spans.values()):
            badges.append('orphan')
        if any(value.unpriced for value in values.values()):
            badges.append('incomplete / unpriced')
        if any(span.kind == 'approval' for span in trace.spans.values()):
            badges.append('approval assertion')
        rows.append(f"<tr><td><a href='/traces/{e(trace.trace_id)}'>{e(trace.service)}</a></td><td>{len(trace.spans)}</td><td>${e(money(total))}</td><td>{sum(trace.redaction_counts.values())}</td><td>{e(', '.join(badges))}</td></tr>")
    return page('Traces', '<table><tr><th>Service</th><th>Spans</th><th>Cost</th><th>PII</th><th>Badges</th></tr>' + ''.join(rows) + '</table>')


def trace_page(trace, pricebook, message=''):
    values = rollup(trace, pricebook)
    children = {None: []}
    orphans = []
    for span in trace.spans.values():
        if span.parent_id and span.parent_id not in trace.spans:
            orphans.append(span)
        else:
            children.setdefault(span.parent_id, []).append(span)
        children.setdefault(span.span_id, [])
    roots = children[None] + orphans
    total = sum((values[span.span_id].subtree_cost for span in roots), start=Decimal('0'))
    max_duration = max([1] + [span.end_ns - span.start_ns for span in trace.spans.values()])
    rows = []

    def render(group, base_depth):
        stack = [(span, base_depth) for span in reversed(group)]
        while stack:
            span, depth = stack.pop()
            row = values[span.span_id]
            duration = (span.end_ns - span.start_ns) / 1e6
            own = 'unpriced (' + str(span.input_tokens + span.output_tokens) + ' tokens)' if row.self_cost is None else '$' + money(row.self_cost)
            details = e(json.dumps({'attributes': span.attributes, 'events': span.events}, ensure_ascii=False, indent=2))
            flags = (' orphan' if span.orphan else '') + (' error' if span.status == 'error' else '')
            width = max(0, min(100, 100 * (span.end_ns - span.start_ns) / max_duration))
            rows.append(f"<div class='span depth-{min(depth, 20)}{flags}'><button class=toggle aria-label='Expand'>▶</button> <b>{e(span.kind)}</b> {e(span.name)} <meter min=0 max=100 value='{width:.3f}' aria-label='Relative duration'></meter> <small>{duration:.1f} ms · self {e(own)} · subtree ${e(money(row.subtree_cost))} · {row.subtree_tokens_in}/{row.subtree_tokens_out} tokens{e(flags)}</small><pre hidden>{details}</pre></div>")
            stack.extend((child, depth + 1) for child in reversed(children[span.span_id]))

    render(children[None], 0)
    if orphans:
        rows.append('<section class=orphan><h2>unparented spans</h2>')
        render(orphans, 1)
        rows.append('</section>')
    notice = '<p class=notice>' + e(message) + '</p>' if message else ''
    report = '<section><h2>Redaction report</h2><p>Counts for the stored trace, accumulated across accepted batches.</p><pre>' + e(json.dumps(trace.redaction_counts, sort_keys=True, indent=2)) + '</pre></section>'
    return page(trace.service, notice + f"<p><b>Total ${e(money(total))}</b> · <a href='/traces/{e(trace.trace_id)}/replay?step=1'>Read-only replay</a></p>" + report + ''.join(rows))


def pack_html(pack):
    body = ''
    for title, value in pack.items():
        body += '<section><h2>' + e(title) + '</h2><pre>' + e(json.dumps(value, indent=2, ensure_ascii=False)) + '</pre></section>'
    return page('DPO evidence pack', body)
