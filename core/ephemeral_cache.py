import time
import threading
from typing import Dict, Any, List, Optional


class EphemeralMemoryStore:
    """RAM-only temporary cache. Auto deletes emails after TTL (default 10 mins)."""

    def __init__(self, default_ttl_seconds: int = 600):
        self.default_ttl = default_ttl_seconds
        self._store: Dict[str, Dict[str, Any]] = {}
        self._timestamps: Dict[str, float] = {}
        self._history_items: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        # background auto-purge thread
        self._cleaner_thread = threading.Thread(target=self._auto_purge_loop, daemon=True)
        self._cleaner_thread.start()

    def set(self, case_id: str, data: Dict[str, Any], history_meta: Optional[Dict[str, Any]] = None):
        with self._lock:
            now = time.time()
            self._store[case_id] = data
            self._timestamps[case_id] = now + self.default_ttl

            if history_meta:
                self._history_items = [h for h in self._history_items if h.get("case_id") != case_id]
                self._history_items.insert(0, history_meta)

    def get(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if case_id not in self._store:
                return None
            if time.time() > self._timestamps.get(case_id, 0):
                self._delete_internal(case_id)
                return None
            return self._store[case_id]

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            now = time.time()
            valid_ids = {cid for cid, exp in self._timestamps.items() if exp > now}
            self._history_items = [h for h in self._history_items if h.get("case_id") in valid_ids]
            return list(self._history_items)

    def purge(self, case_id: str) -> bool:
        """Manually wipe a case from memory right away."""
        with self._lock:
            return self._delete_internal(case_id)

    def purge_all(self):
        """Wipe everything from RAM."""
        with self._lock:
            self._store.clear()
            self._timestamps.clear()
            self._history_items.clear()

    def _delete_internal(self, case_id: str) -> bool:
        existed = case_id in self._store
        self._store.pop(case_id, None)
        self._timestamps.pop(case_id, None)
        self._history_items = [h for h in self._history_items if h.get("case_id") != case_id]
        return existed

    def _auto_purge_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [cid for cid, exp in self._timestamps.items() if now > exp]
                for cid in expired:
                    self._delete_internal(cid)


# singleton instance for the app
memory_store = EphemeralMemoryStore(default_ttl_seconds=600)
