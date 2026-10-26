import unittest
from decimal import Decimal
from agentaudit.clock import FixedClock
from agentaudit.cost import StaticPriceBook,money,rollup,span_self_cost
from agentaudit.ingest import parse
from agentaudit.model import Trace
from agentaudit.redact import Redactor
from agentaudit.sample_data import samples
class TestCost(unittest.TestCase):
 def test_cost_and_unknown(self):
  spans,_,_=parse(samples()[2],Redactor(b"k")); t=Trace("3"*32,"x",{x.span_id:x for x in spans},FixedClock().now()); rows=rollup(t,StaticPriceBook())
  self.assertTrue(any(x.unpriced for x in rows.values())); known=next(x for x in spans if x.model=="demo-small"); self.assertGreater(span_self_cost(known,StaticPriceBook()),Decimal("0"))
 def test_money_handles_large_values(self):
  self.assertEqual(money(Decimal("1e30")),"1000000000000000000000000000000.000000")
  self.assertEqual(money(Decimal("1e999999")),"overflow")
