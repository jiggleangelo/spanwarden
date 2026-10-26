import unittest
from agentaudit.clock import FixedClock
from agentaudit.ingest import parse
from agentaudit.redact import Redactor
from agentaudit.sdk import FakeExporter,Tracer
class TestSDK(unittest.TestCase):
 def test_roundtrip(self):
  ex=FakeExporter(); t=Tracer("svc",ex,FixedClock())
  with t.span("root",{"gen_ai.operation.name":"invoke_agent"}):
   with t.approval("boss@example.test","approved","policy:x"): pass
  doc=t.flush(); spans,_,_=parse(doc,Redactor(b"k")); self.assertEqual(len(spans),2); self.assertEqual(spans[1].parent_id,spans[0].span_id); self.assertIn("agentaudit.approval.decision",spans[1].attributes)
