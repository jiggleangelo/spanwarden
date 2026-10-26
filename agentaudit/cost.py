from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext

class StaticPriceBook:
    def __init__(self, prices=None):
        self.prices=prices or {"demo-large":(Decimal("3.00"),Decimal("15.00")),"demo-small":(Decimal("0.15"),Decimal("0.60"))}
    def price(self, model): return self.prices.get(model)

@dataclass
class RollupRow:
    self_cost: Decimal | None
    subtree_cost: Decimal
    subtree_tokens_in: int
    subtree_tokens_out: int
    tool_calls: int
    llm_calls: int
    unpriced: bool

def span_self_cost(span,pb):
    if span.model:
        price=pb.price(span.model)
        if price is None: return None
        return Decimal(span.input_tokens)*price[0]/Decimal(1_000_000)+Decimal(span.output_tokens)*price[1]/Decimal(1_000_000)+span.extra_cost
    return span.extra_cost

def rollup(trace,pb):
    children={None:[]}
    for span in trace.spans.values():
        parent=span.parent_id if span.parent_id in trace.spans else None
        children.setdefault(parent,[]).append(span.span_id); children.setdefault(span.span_id,[])
    order=[]; stack=list(children[None])
    while stack:
        sid=stack.pop(); order.append(sid); stack.extend(children[sid])
    rows={}
    for sid in reversed(order):
        span=trace.spans[sid]; own=span_self_cost(span,pb); total=own or Decimal("0")
        ti=span.input_tokens; to=span.output_tokens; tools=int(span.kind=="tool"); llms=int(span.kind=="llm"); bad=own is None
        for child in children[sid]:
            row=rows[child]; total+=row.subtree_cost; ti+=row.subtree_tokens_in; to+=row.subtree_tokens_out
            tools+=row.tool_calls; llms+=row.llm_calls; bad|=row.unpriced
        rows[sid]=RollupRow(own,total,ti,to,tools,llms,bad)
    return rows

def money(value):
    try:
        with localcontext() as context:
            context.prec=60
            return str(value.quantize(Decimal("0.000001"),rounding=ROUND_HALF_UP))
    except InvalidOperation:
        return "overflow"
