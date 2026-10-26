from collections import Counter

from .audit import verify_export


def build_dpo_pack(store, audit, signer, config, clock):
    traces = store.list(200)
    spans = sum(len(trace.spans) for trace in traces)
    redactions = Counter()
    for trace in traces:
        redactions.update(trace.redaction_counts)
    approvals = [
        {'actor': entry.actor, 'decision': entry.action.split('.')[-1],
         'policy': entry.authority, 'target': entry.target, 'time': entry.ts,
         'assurance': 'caller-supplied assertion; identity and authority were not authenticated'}
        for entry in audit.entries()
        if entry.action in ('step.approved', 'step.rejected')
    ]
    exported = audit.export(signer)
    verified = verify_export(exported, signer)
    return {
        'Scope': {
            'project': config.get('project', 'AgentAudit demo'),
            'generated_at': clock.now(), 'traces': len(traces), 'spans': spans,
            'date_range': 'bounded in-memory demo session',
        },
        'Data inventory': {
            'stored': 'redacted span names, attributes, events, timings, IDs and costs; public visitor prose is omitted',
            'redacted': 'email, Singapore phone, NRIC/FIN, card-like digit strings and IPv4',
            'never stored': 'raw payloads, request logs or waitlist addresses outside the write-only vault',
        },
        'Redaction summary': {
            'counts': dict(redactions),
            'traces_with_pii': sum(bool(trace.redaction_counts) for trace in traces),
        },
        'Residency and processing': {
            'region': config.get('residency_region', 'local-demo (production target: Singapore region)'),
            'subprocessors': 'none',
        },
        'Retention': {
            'policy': config.get('retention', 'process lifetime with bounded in-memory audit compaction'),
            'caveat': 'All state is lost on restart; production needs durable retention and deletion controls. The fake vault evicts oldest contacts at capacity.',
        },
        'Human approvals register': {
            'entries': approvals,
            'caveat': 'This unauthenticated demo records caller assertions only; it does not prove who approved or their authority.',
        },
        'Audit-chain integrity': {
            'ok': verified.ok, 'head_hash': exported['head_hash'],
            'entries': len(exported['entries']), 'key_id': signer.key_id,
            'version': exported['version'], 'start_seq': exported['start_seq'],
            'anchor_hash': exported['anchor_hash'], 'signature': exported['signature'],
            'method': 'versioned canonical HMAC-SHA256',
            'signature_scope': 'Audit export metadata and chained entries, not the entire evidence pack. The UI downloads a separately signed last-20-entry window.',
            'caveat': 'The in-memory key holder can re-sign altered or truncated data. Production should use durable append-only storage and KMS-backed asymmetric signing.',
        },
        'Mapping table': [
            {'control_area': area, 'evidence': evidence,
             'notice': 'Indicative mapping to support DPO review; verify against current guidance.'}
            for area, evidence in (
                ('Logging and monitoring', 'timeline and bounded audit chain'),
                ('Human oversight', 'unauthenticated approval assertion register'),
                ('Data minimisation', 'ingest redaction and no raw payload storage'),
                ('Accountability', 'actor, action, authority and signed export'),
            )
        ],
    }
