import unittest
from agentaudit.vault import FakeVault
class TestVault(unittest.TestCase):
 def test_write_only(self):
  v=FakeVault(); ref=v.put("email","private@example.test"); self.assertTrue(ref.startswith("vref_")); self.assertEqual(v.count("email"),1); self.assertFalse(hasattr(v,"get")); self.assertNotIn("private@example.test",repr(v))
