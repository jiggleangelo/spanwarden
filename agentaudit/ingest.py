import json
import re
from collections import Counter
from decimal import Decimal, InvalidOperation

from .model import Span, SpanKind

ID32 = re.compile(r"^[0-9a-fA-F]{32}$")
ID16 = re.compile(r"^[0-9a-fA-F]{16}$")
KEY = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
MAX_RESOURCES = 64
MAX_SCOPES = 64
MAX_SPANS = 500
MAX_EVENTS = 128
MAX_ATTRIBUTES = 128
MAX_TEXT = 8192
MAX_EXTRA_COST = Decimal("1000000")
MAX_TOKENS = 10**12


class IngestError(ValueError):
    pass


class ParseCounts(Counter):
    def __init__(self):
        super().__init__()
        self.by_trace = {}


def _mapping(value, message):
    if not isinstance(value, dict):
        raise IngestError(message)
    return value


def _sequence(value, limit, message):
    if not isinstance(value, list) or len(value) > limit:
        raise IngestError(message)
    return value


def _truncate(value):
    text = str(value)
    if len(text) > MAX_TEXT:
        return text[:MAX_TEXT] + "…[truncated]"
    return text


def _redact_scalar(value, redactor, counts):
    original = _truncate(value)
    redacted, found = redactor.redact(original)
    counts.update(found)
    if redacted != original or len(str(value)) > MAX_TEXT:
        return redacted
    return value


def _raw_value(value):
    value = _mapping(value, "invalid attribute value")
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            scalar = value[key]
            if isinstance(scalar, (dict, list)) or scalar is None:
                raise IngestError("invalid attribute value")
            return scalar
    for key in ("arrayValue", "kvlistValue"):
        if key in value:
            try:
                return json.dumps(value[key], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            except (TypeError, ValueError):
                raise IngestError("invalid attribute value") from None
    return ""


def _attrs(items, redactor, counts):
    out = {}
    for item in _sequence(items, MAX_ATTRIBUTES, "invalid attributes"):
        item = _mapping(item, "invalid attribute")
        key = item.get("key", "")
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise IngestError("invalid attribute key")
        safe_key, key_counts = redactor.redact(_truncate(key))
        counts.update(key_counts)
        value = _redact_scalar(_raw_value(item.get("value", {})), redactor, counts)
        if safe_key in out:
            raise IngestError("duplicate attribute key")
        out[safe_key] = value
    return out


def _integer(value):
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return 0


def _token_count(value):
    return min(max(_integer(value), 0), MAX_TOKENS)


def _kind(attrs):
    if "agentaudit.approval.decision" in attrs:
        return SpanKind.APPROVAL
    operation = str(attrs.get("gen_ai.operation.name", ""))
    if operation in ("invoke_agent", "create_agent"):
        return SpanKind.AGENT
    if operation in ("chat", "text_completion", "generate_content", "embeddings"):
        return SpanKind.LLM
    if operation == "execute_tool":
        return SpanKind.TOOL
    inference = str(attrs.get("openinference.span.kind", "")).upper()
    return {
        "AGENT": SpanKind.AGENT,
        "LLM": SpanKind.LLM,
        "TOOL": SpanKind.TOOL,
        "RETRIEVER": SpanKind.RETRIEVER,
    }.get(inference, SpanKind.OTHER)


def parse(payload, redactor):
    payload = _mapping(payload, "invalid JSON document")
    resources = _sequence(payload.get("resourceSpans", []), MAX_RESOURCES, "invalid resource spans")
    spans = []
    services = {}
    counts = ParseCounts()

    for resource_value in resources:
        resource_value = _mapping(resource_value, "invalid resource span")
        resource = _mapping(resource_value.get("resource", {}), "invalid resource")
        resource_counts = Counter()
        resource_attrs = _attrs(resource.get("attributes", []), redactor, resource_counts)
        service = str(resource_attrs.get("service.name", "unknown-service"))
        scopes = _sequence(resource_value.get("scopeSpans", []), MAX_SCOPES, "invalid scope spans")
        resource_trace_ids = set()

        for scope_value in scopes:
            scope_value = _mapping(scope_value, "invalid scope span")
            objects = scope_value.get("spans", [])
            if not isinstance(objects, list):
                raise IngestError("invalid spans")
            if len(spans) + len(objects) > MAX_SPANS:
                raise IngestError("too many spans")

            for value in objects:
                obj = _mapping(value, "invalid span")
                span_counts = Counter()
                trace_id = str(obj.get("traceId", ""))
                span_id = str(obj.get("spanId", ""))
                parent_id = str(obj.get("parentSpanId", "") or "")
                if not ID32.fullmatch(trace_id) or not ID16.fullmatch(span_id) or (parent_id and not ID16.fullmatch(parent_id)):
                    raise IngestError("invalid span identifier")

                attrs = _attrs(obj.get("attributes", []), redactor, span_counts)
                name = _redact_scalar(_truncate(obj.get("name", "unnamed")), redactor, span_counts)
                events = []
                for event_value in _sequence(obj.get("events", []), MAX_EVENTS, "invalid events"):
                    event = _mapping(event_value, "invalid event")
                    event_name = _redact_scalar(_truncate(event.get("name", "event")), redactor, span_counts)
                    event_attrs = _attrs(event.get("attributes", []), redactor, span_counts)
                    events.append({"name": str(event_name), "attributes": event_attrs})

                start = _integer(obj.get("startTimeUnixNano"))
                end = _integer(obj.get("endTimeUnixNano"))
                if end < start:
                    end = start
                    attrs["agentaudit.time_clamped"] = True
                status_obj = _mapping(obj.get("status", {}), "invalid status")
                code = status_obj.get("code", 0)
                status = "ok" if code == 1 else "error" if code == 2 else "unset"
                model = attrs.get("gen_ai.request.model") or attrs.get("gen_ai.response.model") or attrs.get("llm.model_name")
                try:
                    extra = Decimal(str(attrs.get("agentaudit.cost_usd", 0)))
                except (InvalidOperation, ValueError):
                    raise IngestError("invalid extra cost") from None
                if not extra.is_finite() or not Decimal("0") <= extra <= MAX_EXTRA_COST:
                    raise IngestError("invalid extra cost")

                spans.append(Span(
                    trace_id, span_id, parent_id or None, str(name), _kind(attrs), start, end,
                    status, attrs, events, str(model) if model else None,
                    _token_count(attrs.get("gen_ai.usage.input_tokens", attrs.get("llm.token_count.prompt", 0))),
                    _token_count(attrs.get("gen_ai.usage.output_tokens", attrs.get("llm.token_count.completion", 0))),
                    extra, attrs.get("gen_ai.tool.name") or attrs.get("tool.name"),
                ))
                services[trace_id] = service
                resource_trace_ids.add(trace_id)
                counts.update(span_counts)
                counts.by_trace.setdefault(trace_id, Counter()).update(span_counts)

        counts.update(resource_counts)
        for trace_id in resource_trace_ids:
            counts.by_trace.setdefault(trace_id, Counter()).update(resource_counts)

    return spans, services, counts


def ingest(payload, redactor, store, audit, pinned=False):
    try:
        spans, services, counts = parse(payload, redactor)
        grouped = {}
        for span in spans:
            grouped.setdefault(span.trace_id, []).append(span)

        trace_ids = []
        for trace_id, group in grouped.items():
            trace_counts = counts.by_trace.get(trace_id, Counter())
            store.put_spans(group, services[trace_id], trace_counts, pinned)
            audit.append(
                "ingest:" + services[trace_id], "trace.ingested", trace_id,
                details={"spans": len(group), "redactions": sum(trace_counts.values())},
            )
            for span in group:
                if span.kind == SpanKind.APPROVAL:
                    decision = str(span.attributes.get("agentaudit.approval.decision", "rejected"))
                    action = "step.approved" if decision == "approved" else "step.rejected"
                    audit.append(
                        str(span.attributes.get("agentaudit.approval.approver", "unknown")), action,
                        trace_id + ":" + span.span_id,
                        str(span.attributes.get("agentaudit.approval.policy", "n/a")),
                        {"parent_span_id": span.parent_id or "", "assertion": "caller-supplied; unverified"},
                    )
            trace_ids.append(trace_id)
        return trace_ids, dict(counts)
    except IngestError:
        raise
    except (TypeError, ValueError, AttributeError, KeyError) as error:
        raise IngestError("invalid trace document") from error
