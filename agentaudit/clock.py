from datetime import datetime, timezone

class SystemClock:
    def now(self): return datetime.now(timezone.utc).isoformat()
    def time_ns(self): return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

class FixedClock:
    def __init__(self, value="2026-10-24T12:00:00+00:00", ns=1792843200000000000):
        self.value, self.ns = value, ns
    def now(self): return self.value
    def time_ns(self): return self.ns
