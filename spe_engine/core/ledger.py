"""
AttestationLedger — Append-only hash-chain for tamper-evident sequencing.

The ledger creates a cryptographic chain where each entry is bound to
the previous one via:

    entry_hash = SHA-256(prev_hash | capsule_hash | t_run)

This makes any insertion, deletion, or modification detectable.
The ledger uses SQLite for portability — each proof bundle carries
its own self-contained ledger.
"""

import hashlib
import sqlite3
import time
from typing import Optional, Tuple


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(prev_hash: str, capsule_hash: str, t_run: int) -> str:
    """Compute the chained hash for a new ledger entry."""
    payload = f"{prev_hash}|{capsule_hash}|{t_run}".encode("utf-8")
    return sha256_hex(payload)


class AttestationLedger:
    """
    SQLite-backed append-only hash chain.
    
    Genesis entry uses prev_hash = "0" * 64 (64 zero characters).
    Each subsequent entry chains to the previous entry_hash.
    """

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                '''
                CREATE TABLE IF NOT EXISTS ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    t_run INTEGER NOT NULL,
                    capsule_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
                '''
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_ledger_id ON ledger(id);")

    def _get_last_entry(self) -> Optional[Tuple[int, int, str, str, str]]:
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "SELECT id, t_run, capsule_hash, prev_hash, entry_hash "
                "FROM ledger ORDER BY id DESC LIMIT 1;"
            )
            return cur.fetchone()

    def append(self, capsule_hash: str, t_run: Optional[int] = None) -> str:
        """
        Append a new entry to the hash chain.
        
        Returns the entry_hash of the new entry.
        """
        if t_run is None:
            t_run = int(time.time())

        last = self._get_last_entry()
        prev_hash = last[4] if last else self.GENESIS_PREV_HASH

        entry_hash = chain_hash(prev_hash, capsule_hash, t_run)

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO ledger (t_run, capsule_hash, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?);",
                (t_run, capsule_hash, prev_hash, entry_hash),
            )

        return entry_hash

    def verify(self) -> bool:
        """
        Verify the entire hash-chain integrity.
        
        Returns True if every entry's hash is correctly computed from
        the previous entry. Returns False if any tampering is detected.
        """
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "SELECT id, t_run, capsule_hash, prev_hash, entry_hash "
                "FROM ledger ORDER BY id ASC;"
            )
            rows = cur.fetchall()

        expected_prev = self.GENESIS_PREV_HASH
        for id_, t_run, capsule_hash, prev_hash, entry_hash in rows:
            if prev_hash != expected_prev:
                return False
            expected_entry = chain_hash(expected_prev, capsule_hash, t_run)
            if entry_hash != expected_entry:
                return False
            expected_prev = entry_hash

        return True

    def get_tip(self) -> Optional[str]:
        """Return the latest entry_hash (tip of the chain)."""
        last = self._get_last_entry()
        return last[4] if last else None

    def count(self) -> int:
        """Return the total number of entries."""
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute("SELECT COUNT(*) FROM ledger;")
            return cur.fetchone()[0]
