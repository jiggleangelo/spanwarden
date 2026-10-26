from collections import Counter, OrderedDict
from copy import deepcopy
from threading import Lock

from .model import Trace


class StoreError(ValueError):
    pass


class MemoryStore:
    def __init__(self, clock, max_traces=200, max_spans=20000, max_spans_per_trace=1000):
        self.clock = clock
        self.max_traces = max_traces
        self.max_spans = max_spans
        self.max_spans_per_trace = max(1, int(max_spans_per_trace))
        self._traces = {}
        self._order = OrderedDict()
        self._lock = Lock()

    def put_spans(self, spans, service, redaction_counts, pinned=False):
        spans = list(spans)
        if not spans:
            return []
        with self._lock:
            incoming = set()
            incoming_by_trace = Counter()
            touched = set()
            for span in spans:
                marker = (span.trace_id, span.span_id)
                if marker in incoming:
                    raise StoreError("duplicate span identifier")
                incoming.add(marker)
                incoming_by_trace[span.trace_id] += 1
                existing = self._traces.get(span.trace_id)
                if existing is not None:
                    if existing.pinned and not pinned:
                        raise StoreError("pinned traces are read-only")
                    if span.span_id in existing.spans:
                        raise StoreError("span identifiers are append-only")
                touched.add(span.trace_id)

            for trace_id, count in incoming_by_trace.items():
                existing_count = len(self._traces[trace_id].spans) if trace_id in self._traces else 0
                if existing_count + count > self.max_spans_per_trace:
                    raise StoreError("trace span limit exceeded")

            new_traces = sum(trace_id not in self._traces for trace_id in touched)
            projected_traces = len(self._traces) + new_traces
            projected_spans = sum(len(trace.spans) for trace in self._traces.values()) + len(spans)
            victims = []
            for trace_id in self._order:
                if projected_traces <= self.max_traces and projected_spans <= self.max_spans:
                    break
                trace = self._traces[trace_id]
                if not trace.pinned and trace_id not in touched:
                    victims.append(trace_id)
                    projected_traces -= 1
                    projected_spans -= len(trace.spans)
            if projected_traces > self.max_traces or projected_spans > self.max_spans:
                raise StoreError("storage capacity exceeded")

            for trace_id in victims:
                del self._traces[trace_id]
                del self._order[trace_id]

            for span in spans:
                trace = self._traces.get(span.trace_id)
                if trace is None:
                    trace = Trace(span.trace_id, service, {}, self.clock.now(), {}, pinned)
                    self._traces[span.trace_id] = trace
                    self._order[span.trace_id] = None
                trace.spans[span.span_id] = span
                trace.pinned |= pinned

            for trace_id in touched:
                trace = self._traces[trace_id]
                trace.redaction_counts = dict(Counter(trace.redaction_counts) + Counter(redaction_counts))
                for span in trace.spans.values():
                    span.orphan = bool(span.parent_id and span.parent_id not in trace.spans)
            return list(dict.fromkeys(span.trace_id for span in spans))

    def get(self, trace_id):
        with self._lock:
            trace = self._traces.get(trace_id)
            return deepcopy(trace) if trace is not None else None

    def list(self, limit=50):
        with self._lock:
            trace_ids = list(self._order.keys())[-limit:]
            return [deepcopy(self._traces[trace_id]) for trace_id in reversed(trace_ids)]
