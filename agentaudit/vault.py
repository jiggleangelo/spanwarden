import secrets
from collections import Counter, OrderedDict
from threading import Lock
from typing import Protocol


class Vault(Protocol):
    def put(self, kind: str, value: str) -> str: ...


class FakeVault:
    """Write-only in-memory fake; oldest contacts are evicted at capacity."""
    __slots__ = ('_put', '_count')

    def __init__(self, max_entries=1000):
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError('max_entries must be positive')
        values = OrderedDict()
        counts = Counter()
        lock = Lock()

        def put(kind, value):
            kind = 'email' if kind == 'email' else 'other'
            if not isinstance(value, str) or len(value) > 254:
                raise ValueError('Invalid vault value')
            with lock:
                reference = 'vref_' + secrets.token_hex(16)
                while reference in values:
                    reference = 'vref_' + secrets.token_hex(16)
                if len(values) >= max_entries:
                    _, (old_kind, _) = values.popitem(last=False)
                    counts[old_kind] -= 1
                values[reference] = (kind, value)
                counts[kind] += 1
                return reference

        def count(kind):
            with lock:
                return counts.get(kind if kind in ('email', 'other') else 'other', 0)

        self._put, self._count = put, count

    def put(self, kind, value):
        return self._put(kind, value)

    def count(self, kind):
        return self._count(kind)
