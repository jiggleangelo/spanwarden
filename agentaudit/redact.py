import hashlib
import hmac
import re
import unicodedata
from collections import Counter


_EMAIL = re.compile(
    r"(?<![\w.+-])([\w.!#$%&'*+/=?^`{|}~-]+@[\w](?:[\w.-]*[\w])?\.[^\W_]{2,63})(?![\w.-])",
    re.UNICODE,
)
_PHONE_SG = re.compile(r"(?<!\w)(?:\+65[\s.-]?)?[689]\d{3}[\s.-]?\d{4}(?!\d)")
_NRIC = re.compile(r"(?<![A-Z0-9])[STFGM]\d{7}[A-Z](?![A-Z0-9])", re.IGNORECASE)
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _without_format_characters(value):
    return "".join(character for character in value if unicodedata.category(character) != "Cf")


def _normalise(value):
    # Canonically normalize text without compatibility-folding unrelated
    # characters such as the horizontal ellipsis into different output.
    return unicodedata.normalize("NFC", _without_format_characters(value))


def _valid_ipv4(value):
    try:
        parts = value.split(".")
        return len(parts) == 4 and all(
            part.isascii()
            and part.isdigit()
            and 0 <= int(part) <= 255
            and (part == "0" or not part.startswith("0"))
            for part in parts
        )
    except (TypeError, ValueError):
        return False


def _valid_card(value):
    digits = re.sub(r"[^0-9]", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        number = int(character)
        if index % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _valid_nric(value):
    value = value.upper()
    if not re.fullmatch(r"[STFGM]\d{7}[A-Z]", value):
        return False
    prefix = value[0]
    weighted = sum(
        int(character) * weight
        for character, weight in zip(value[1:8], (2, 7, 6, 5, 4, 3, 2))
    )
    if prefix in "TG":
        weighted += 4
    tables = {
        "S": "JZIHGFEDCBA",
        "T": "JZIHGFEDCBA",
        "F": "XWUTRQPNMLK",
        "G": "XWUTRQPNMLK",
        "M": "KLJNPQRTUWX",
    }
    return value[-1] == tables[prefix][weighted % 11]


def _canonical(kind, value):
    if kind in {"PHONE_SG", "CARD"}:
        return re.sub(r"\D", "", value)
    if kind == "EMAIL":
        return value.casefold()
    if kind == "NRIC":
        return value.upper()
    return value


class Redactor:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._key = bytes(key)

    def token(self, kind, value):
        kind = str(kind).upper()
        value = _canonical(kind, _normalise(str(value)))
        digest = hmac.new(
            self._key,
            (kind + "\0" + value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:12]
        return "[{}#{}]".format(kind, digest)

    def pseudonymize(self, kind, value):
        return self.token(kind, value)

    def redact(self, text):
        text = _normalise(str(text))
        counts = Counter()

        def replace(pattern, kind, validator=None, count_invalid_candidate=False):
            nonlocal text

            def replacement(match):
                value = match.group(0)
                if validator is not None and not validator(value):
                    if count_invalid_candidate:
                        counts[kind + "_CANDIDATE"] += 1
                    return value
                counts[kind] += 1
                return self.token(kind, value)

            text = pattern.sub(replacement, text)

        # Avoid invoking the comparatively expensive email expression for the
        # overwhelmingly common case where an email is impossible.
        if "@" in text:
            replace(_EMAIL, "EMAIL")
        replace(_NRIC, "NRIC", _valid_nric)
        replace(_IPV4, "IPV4", _valid_ipv4)
        replace(_CARD, "CARD", _valid_card, count_invalid_candidate=True)
        replace(_PHONE_SG, "PHONE_SG")
        return text, counts
