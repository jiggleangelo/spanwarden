import copy,threading,unittest
from agentaudit.audit import AuditLog,HmacSigner,verify_export
from agentaudit.clock import FixedClock
class TestAudit(unittest.TestCase):
 def test_export_and_tamper(self):
  a=AuditLog(FixedClock()); s=HmacSigner(b"x"); a.append("a","act","t"); d=a.export(s); self.assertTrue(verify_export(d,s).ok); bad=copy.deepcopy(d); bad["entries"][0]["details"]["x"]=1; self.assertEqual(verify_export(bad,s).reason,"hash_mismatch")
 def test_concurrent(self):
  a=AuditLog(FixedClock()); ts=[threading.Thread(target=lambda:[a.append("a","x","t") for _ in range(20)]) for _ in range(8)]
  [t.start() for t in ts]; [t.join() for t in ts]; self.assertTrue(verify_export(a.export(HmacSigner(b"x")),HmacSigner(b"x")).ok)
