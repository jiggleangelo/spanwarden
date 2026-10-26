import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from threading import Lock

ZERO = "0" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    target: str
    authority: str
    details: dict
    prev_hash: str
    hash: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    first_bad_seq: int | None = None
    reason: str = "ok"


class HmacSigner:
    def __init__(self, key, key_id=None):
        self.key = key
        self.key_id = key_id or hashlib.sha256(key).hexdigest()[:12]

    def sign(self, head, count, version=2, key_id=None, start_seq=0, anchor_hash=ZERO):
        body = {
            "version": version,
            "key_id": key_id or self.key_id,
            "count": count,
            "start_seq": start_seq,
            "anchor_hash": anchor_hash,
            "head_hash": head,
        }
        return hmac.new(self.key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, clock, max_entries=10000):
        self.clock = clock
        self.max_entries = max(1, int(max_entries))
        self._items = []
        self._start_seq = 0
        self._anchor_hash = ZERO
        self._lock = Lock()

    @staticmethod
    def _field(value):
        text = str(value)
        return text if len(text) <= 256 else text[:256] + "…"

    def append(self, actor, action, target, authority="n/a", details=None):
        with self._lock:
            safe_details = details if isinstance(details, dict) else {"value": self._field(details)}
            try:
                canonical(safe_details)
            except (TypeError, ValueError):
                safe_details = {"value": "unserializable details omitted"}
            base = {
                "seq": self._start_seq + len(self._items),
                "ts": self._field(self.clock.now()),
                "actor": self._field(actor),
                "action": self._field(action),
                "target": self._field(target),
                "authority": self._field(authority),
                "details": safe_details,
                "prev_hash": self._items[-1].hash if self._items else self._anchor_hash,
            }
            entry = AuditEntry(**base, hash=hashlib.sha256(canonical(base).encode("utf-8")).hexdigest())
            self._items.append(entry)
            if len(self._items) > self.max_entries:
                removed = self._items.pop(0)
                self._anchor_hash = removed.hash
                self._start_seq = removed.seq + 1
            return entry

    def entries(self):
        with self._lock:
            return list(self._items)

    def tail(self, limit):
        limit = max(0, int(limit))
        with self._lock:
            return list(self._items[-limit:]) if limit else []

    def export(self, signer):
        with self._lock:
            entries = [asdict(item) for item in self._items]
            start_seq = self._start_seq
            anchor_hash = self._anchor_hash
        head = entries[-1]["hash"] if entries else anchor_hash
        count = len(entries)
        return {
            "version": 2,
            "key_id": signer.key_id,
            "start_seq": start_seq,
            "anchor_hash": anchor_hash,
            "entries": entries,
            "head_hash": head,
            "signature": signer.sign(head, count, 2, signer.key_id, start_seq, anchor_hash),
        }


def verify_export(doc, signer):
    try:
        if not isinstance(doc, dict):
            return VerifyResult(False, 0, "invalid_document")
        version = doc.get("version")
        key_id = doc.get("key_id")
        start_seq = doc.get("start_seq", 0)
        anchor_hash = doc.get("anchor_hash", ZERO)
        entries = doc.get("entries")
        if version != 2 or key_id != signer.key_id:
            return VerifyResult(False, None, "key_or_version_mismatch")
        if not isinstance(start_seq, int) or start_seq < 0 or not isinstance(anchor_hash, str) or len(anchor_hash) != 64:
            return VerifyResult(False, 0, "invalid_document")
        if not isinstance(entries, list):
            return VerifyResult(False, 0, "invalid_document")

        previous = anchor_hash
        required = {"seq", "ts", "actor", "action", "target", "authority", "details", "prev_hash", "hash"}
        for offset, entry in enumerate(entries):
            sequence = start_seq + offset
            if not isinstance(entry, dict) or set(entry) != required or not isinstance(entry.get("details"), dict):
                return VerifyResult(False, sequence, "invalid_entry")
            if entry.get("seq") != sequence:
                return VerifyResult(False, sequence, "seq_gap")
            if entry.get("prev_hash") != previous:
                return VerifyResult(False, sequence, "prev_mismatch")
            base = {key: value for key, value in entry.items() if key != "hash"}
            actual = hashlib.sha256(canonical(base).encode("utf-8")).hexdigest()
            if not isinstance(entry.get("hash"), str) or entry["hash"] != actual:
                return VerifyResult(False, sequence, "hash_mismatch")
            previous = entry["hash"]

        if doc.get("head_hash") != previous:
            return VerifyResult(False, None, "head_mismatch")
        signature = doc.get("signature")
        if not isinstance(signature, str):
            return VerifyResult(False, None, "bad_signature")
        expected = signer.sign(previous, len(entries), version, key_id, start_seq, anchor_hash)
        if not hmac.compare_digest(signature, expected):
            return VerifyResult(False, None, "bad_signature")
        return VerifyResult(True)
    except (TypeError, ValueError, OverflowError):
        return VerifyResult(False, 0, "invalid_document")
