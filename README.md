# spanwarden

Audit trail for AI agents in Singapore: spanwarden

**Try the live demo (made-up data):** https://try-spanwarden.manykiln.com/  
**Product page:** https://spanwarden.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. Nothing here is for sale.

- Status: prototype (29 automated tests passing in an isolated container; reviewed by an outside AI model)
- Runs on the Python 3.12 standard library; external services are faked
- Licence: MIT
- Issues and pull requests are not monitored.

---

# AgentAudit MVP

AgentAudit is a Python stdlib demo of ingest-time redaction, nested trace timelines, Decimal cost rollups, a tamper-evident audit chain and a DPO evidence pack. All bundled data is made up. The pack supplies evidence to support review, not legal advice or a claim of PDPA compliance.

## Run

Python 3.12; no packages or outbound network access required.

```sh
python3 demo.py
PORT=9000 python3 demo.py
python3 -m unittest discover -s tests -v
python3 -m unittest tests.test_e2e_demo -v
```

Open http://localhost:8080. The entry point binds to 0.0.0.0. The end-to-end test uses fake connections, clock, exporter, vault, prices and in-memory stores; it forbids real sockets. Existing HTTP integration tests use localhost.

## Tour

1. Open Traces and inspect nested steps, duration bars, self/subtree costs and unparented spans.
2. Submit the prefilled fake-PII trace. Its destination page includes accumulated redaction counts.
3. Verify the live audit chain and download a signed last-20-entry export window.
4. Submit the pre-altered window in Tamper test and inspect the exact failing sequence. A downloaded, unmodified window verifies successfully.
5. Open the printable DPO pack or /pack.json.
6. Optionally record an anonymous pricing preference or separately join the waitlist.

## Ingest and public-demo privacy

POST /v1/traces accepts application/json with Content-Length and a maximum 64 KB body. Success returns accepted (span count), trace_ids and redactions. Invalid input receives a generic error without echoed values. The parser limits resources, scopes, spans, attributes and events. A trace may retain at most 1,000 spans, and cycle validation is linear in the retained trace size. Existing span IDs and pinned sample writes are rejected. Missing parents are reattached when a later batch supplies them.

The public server has no authentication or tenancy. Consequently, visitor prose is omitted before storage, including service names, arbitrary attribute keys/values, event text, tool labels and approval-policy prose. The public view retains structural fields, numeric costs, approval decisions and detected redaction tokens; unknown models remain explicitly unpriced. This prevents arbitrary names, addresses or phishing text from becoming public content. Bundled fictional traces retain their descriptive labels. The internal ingest API retains its general redacted tracing behavior for trusted callers.

Redaction normalizes Unicode and removes invisible format characters before detection. It detects international email addresses, SG phone numbers, NRIC/FIN, Luhn-valid cards and IPv4. Other card-shaped values are removed as CARD_CANDIDATE. Email matching is skipped when the bounded input contains no `@`. Keyed tokens permit correlation. Pattern matching alone is not a general personal-data classifier.

## Bounded demo behavior

The server caps active connections at 32, sets a 10-second socket inactivity timeout and uses daemon request threads. A fully occupied server closes excess connections. Request logging is disabled.

A signed, HttpOnly, SameSite cookie supplies an ephemeral rate-limit identity. The cookie also has Secure when the handler is served over TLS. Each identity permits 20 requests per second. A second source-address admission bucket permits 100 requests per second, so dropping or renewing the cookie does not reset the outer limit. Both limiters retain at most 1,024 keyed identities with constant-time eviction; source addresses are represented by keyed digests and are not retained raw. Production deployment should additionally enforce admission limits at the reverse proxy or edge and add authentication.

Trace storage retains at most 200 traces, 20,000 spans overall and 1,000 spans per trace by default. Audit storage retains at most 10,000 entries behind a signed compaction anchor. The audit HTML page renders only the latest 100 entries. The public export and tamper form use the latest 20 entries, preserving their original sequence and preceding hash and signing that window. The entire live chain is verified by /audit/verify. Tamper uploads have a separate bounded 2 MB limit; trace and other form uploads remain limited to 64 KB.

Pricing counters have exactly four buckets: Solo $19, Team $49, Enterprise and other. Arbitrary submitted strings are never published as counter keys. Counters saturate at 2^31-1. The fake vault retains at most 1,000 contacts, evicts the oldest at capacity, limits stored value length and has only two bounded kind counters. It exposes no read operation. Vault counts describe currently retained records. Contact details are not linked to pricing records.

## Configuration and limitations

- PORT defaults to 8080.
- REDACTION_KEY and AUDIT_SIGNING_KEY default to independent random process keys.
- The evidence pack labels residency local-demo (production target: Singapore region); it does not assert actual SG hosting.

All state disappears on restart. Prices, exporter and vault are fakes; there is no model execution or external delivery. Replay is read-only. Approval actors and authorities are unauthenticated caller assertions. HMAC integrity depends on trusting the shared-secret holder, who can alter and re-sign data. The pack includes the full retained audit export's signature and its metadata; that signature does not sign the whole pack. Production needs durable retention, authentication, a protected vault, edge admission controls and asymmetric signing.
