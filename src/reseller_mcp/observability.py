from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any


class OperationMetrics:
    """Process-local metrics without account names, arguments, or result payloads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: defaultdict[tuple[str, str], int] = defaultdict(int)
        self._duration_ms: defaultdict[tuple[str, str], float] = defaultdict(float)

    def record(self, capability_id: str, outcome: str, duration_ms: float) -> None:
        key = (capability_id, outcome)
        with self._lock:
            self._counts[key] += 1
            self._duration_ms[key] += max(duration_ms, 0)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            items = []
            for key in sorted(self._counts):
                count = self._counts[key]
                duration = self._duration_ms[key]
                items.append(
                    {
                        "capability_id": key[0],
                        "outcome": key[1],
                        "count": count,
                        "total_duration_ms": round(duration, 2),
                        "average_duration_ms": round(duration / count, 2),
                    }
                )
        return {"items": items, "series": len(items)}
