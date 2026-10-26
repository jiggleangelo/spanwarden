import unittest
from agentaudit.audit import AuditLog
from agentaudit.clock import FixedClock
from agentaudit.ingest import IngestError,MAX_TOKENS,ingest,parse
from agentaudit.redact import Redactor
from agentaudit.sample_data import samples
from agentaudit.store import MemoryStore
class TestIngest(unittest.TestCase):
 def test_samples_redacted_and_orphan(self):
  c=FixedClock(); s=MemoryStore(c); a=AuditLog(c)
  for d in samples(): ingest(d,Redactor(b"k"),s,a)
  self.assertNotIn("example.test",repr(s._traces)); self.assertTrue(any(x.orphan for x in s.get("2"*32).spans.values()))
 def test_bad_id(self):
  d=samples()[0]; d["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]="secret@example.test"
  with self.assertRaisesRegex(IngestError,"identifier"): parse(d,Redactor(b"k"))
 def test_rejects_oversized_cost(self):
  d=samples()[0]; d["resourceSpans"][0]["scopeSpans"][0]["spans"][0].setdefault("attributes",[]).append({"key":"agentaudit.cost_usd","value":{"doubleValue":1e30}})
  with self.assertRaisesRegex(IngestError,"extra cost"): parse(d,Redactor(b"k"))
 def test_caps_token_counts(self):
  d=samples()[0]; attrs=d["resourceSpans"][0]["scopeSpans"][0]["spans"][0].setdefault("attributes",[])
  attrs.extend([{"key":"gen_ai.usage.input_tokens","value":{"intValue":10**30}},{"key":"gen_ai.usage.output_tokens","value":{"intValue":-50}}])
  spans,_,_=parse(d,Redactor(b"k")); self.assertEqual(spans[0].input_tokens,MAX_TOKENS); self.assertEqual(spans[0].output_tokens,0)
