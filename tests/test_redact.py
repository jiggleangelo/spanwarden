import unittest
from agentaudit.redact import Redactor


class TestRedact(unittest.TestCase):
 def test_detectors(self):
  r=Redactor(b"a"*32); raw="a@example.test +65 8123 4567 S0000001I 4111 1111 1111 1111 8.8.8.8"; out,c=r.redact(raw)
  self.assertNotIn("example",out); self.assertEqual(set(c),{"EMAIL","PHONE_SG","NRIC","CARD","IPV4"}); self.assertEqual(out,r.redact(raw)[0]); self.assertNotEqual(out,Redactor(b"b"*32).redact(raw)[0])
 def test_invalid_card(self): self.assertEqual(Redactor(b"x").redact("4111 1111 1111 1112")[1]["CARD"],0)
 def test_spaced_luhn_card_is_not_only_a_candidate(self):
  output,counts=Redactor(b"x").redact("pay with 4111 1111 1111 1111")
  self.assertEqual(counts["CARD"],1)
  self.assertEqual(counts["CARD_CANDIDATE"],0)
  self.assertIn("[CARD#",output)
  self.assertNotIn("4111",output)
