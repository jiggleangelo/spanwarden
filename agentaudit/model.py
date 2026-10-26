from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum

class SpanKind(StrEnum):
    AGENT="agent"; LLM="llm"; TOOL="tool"; RETRIEVER="retriever"; APPROVAL="approval"; OTHER="other"

@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_id: str | None
    name: str
    kind: SpanKind
    start_ns: int
    end_ns: int
    status: str
    attributes: dict
    events: list
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    extra_cost: Decimal = Decimal("0")
    tool_name: str | None = None
    orphan: bool = False

@dataclass
class Trace:
    trace_id: str
    service: str
    spans: dict[str, Span]
    received_at: str
    redaction_counts: dict[str, int] = field(default_factory=dict)
    pinned: bool = False
