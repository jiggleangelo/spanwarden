import unittest

from agentaudit.redact import Redactor
from demo import safe_text


class TestSafeText(unittest.TestCase):
    def test_redactor_tokens_survive_visitor_text_filter(self):
        redactor = Redactor(b'regression-test-key')
        examples = (
            ('EMAIL', 'fake.user@example.test'),
            ('NRIC', 'S0000001I'),
            ('PHONE_SG', '+65 8123 4567'),
            ('IPV4', '8.8.8.8'),
            ('CARD', '4111111111111111'),
            ('CARD_CANDIDATE', '4111111111111112'),
        )
        tokens = []
        for kind, value in examples:
            with self.subTest(kind=kind):
                token = redactor.token(kind, value)
                tokens.append(token)
                self.assertEqual(safe_text(token), 'Visitor text omitted ' + token)
                self.assertEqual(
                    safe_text('Private visitor prose ' + token + ' ' + value),
                    'Visitor text omitted ' + token,
                )
        self.assertEqual(
            safe_text('Private prefix ' + ' private separator '.join(tokens) + ' private suffix'),
            'Visitor text omitted ' + ' '.join(tokens),
        )

    def test_plain_text_and_malformed_tokens_are_omitted(self):
        for value in (
            'Private visitor prose fake.user@example.test',
            '[EMAIL#0123456789a]',
            '[EMAIL#0123456789abc]',
            '[EMAIL#0123456789abcdef]',
            '[EMAIL#ABCDEF012345]',
            '[EMAIL#0123456789ag]',
            '[UNKNOWN#0123456789ab]',
            '[EMAIL#0123456789ab',
        ):
            with self.subTest(value=value):
                self.assertEqual(safe_text(value), 'Visitor text omitted ')


if __name__ == '__main__':
    unittest.main()
