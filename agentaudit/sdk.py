import contextvars, json, secrets, urllib.request
from contextlib import contextmanager


class FakeExporter:
    def __init__(self):
        self.batches = []

    def export(self, doc):
        self.batches.append(doc)


class HttpExporter:
    def __init__(self, url):
        self.url = url

    def export(self, doc):
        request = urllib.request.Request(
            self.url,
            json.dumps(doc).encode(),
            {"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10):
            pass


class SpanHandle:
    def __init__(self, obj):
        self.obj = obj


class Tracer:
    def __init__(self, service, exporter, clock):
        self.service = service
        self.exporter = exporter
        self.clock = clock
        self.pending = []
        self.current = contextvars.ContextVar("agentaudit_parent", default=None)

    @contextmanager
    def span(self, name, kind_attr=None, **attrs):
        current = self.current.get()
        trace_id = current[0] if current else secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        parent_id = current[1] if current else ""
        obj = {
            "traceId": trace_id,
            "spanId": span_id,
            "parentSpanId": parent_id,
            "name": name,
            "startTimeUnixNano": str(self.clock.time_ns()),
            "attributes": [],
        }
        merged = dict(kind_attr or {})
        merged.update(attrs)
        for key, value in merged.items():
            field = (
                "boolValue" if isinstance(value, bool)
                else "intValue" if isinstance(value, int)
                else "doubleValue" if isinstance(value, float)
                else "stringValue"
            )
            obj["attributes"].append({"key": key, "value": {field: value}})

        # Preserve creation order so parents precede their nested children in OTLP output.
        self.pending.append(obj)
        token = self.current.set((trace_id, span_id))
        handle = SpanHandle(obj)
        try:
            yield handle
            obj["status"] = {"code": 1}
        except Exception:
            obj["status"] = {"code": 2}
            raise
        finally:
            obj["endTimeUnixNano"] = str(
                max(self.clock.time_ns(), int(obj["startTimeUnixNano"]))
            )
            self.current.reset(token)

    def llm(self, model, input_tokens=0, output_tokens=0):
        return self.span(
            "LLM",
            {
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": model,
                "gen_ai.usage.input_tokens": input_tokens,
                "gen_ai.usage.output_tokens": output_tokens,
            },
        )

    def tool(self, name):
        return self.span(
            name,
            {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": name},
        )

    def approval(self, approver, decision, policy):
        return self.span(
            "Human approval",
            {
                "agentaudit.approval.approver": approver,
                "agentaudit.approval.decision": decision,
                "agentaudit.approval.policy": policy,
            },
        )

    def flush(self):
        doc = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": self.service},
                            }
                        ]
                    },
                    "scopeSpans": [{"spans": self.pending}],
                }
            ]
        }
        self.exporter.export(doc)
        self.pending = []
        return doc
