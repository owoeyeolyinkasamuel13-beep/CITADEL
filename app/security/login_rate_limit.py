"""Local development login throttling backed by a process-shared SQLite file."""

import hashlib
import math
import os
import sqlite3
import time
from pathlib import Path


WINDOW_SECONDS = 10 * 60
PERSONNEL_ATTEMPT_LIMIT = 5
SOURCE_ATTEMPT_LIMIT = 60
DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[2] / ".login_rate_limit.sqlite3"


class LoginRateLimitStoreUnavailable(RuntimeError):
    """Raised when login attempts cannot be safely rate limited."""


class SQLiteLoginRateLimiter:
    """Sliding-window throttling shared by workers on one local host.

    Production deployments must use a distributed rate limiter; this local
    SQLite store is enabled only when APP_ENV=development is explicit.
    """

    def __init__(self, database_path: str | Path | None = None):
        configured_path = database_path or os.getenv(
            "LOGIN_RATE_LIMIT_DB_PATH",
            str(DEFAULT_DATABASE_PATH),
        )
        if str(configured_path) == ":memory:":
            raise LoginRateLimitStoreUnavailable(
                "In-memory login rate limiting is not supported"
            )
        self.database_path = Path(configured_path).expanduser().resolve()

    @classmethod
    def from_environment(cls) -> "SQLiteLoginRateLimiter":
        environment = os.getenv("APP_ENV", "").strip().lower()
        if environment != "development":
            raise LoginRateLimitStoreUnavailable(
                "The local limiter is available only with APP_ENV=development"
            )
        return cls()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = None
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(self.database_path), timeout=5)
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    dimension TEXT NOT NULL,
                    dimension_key TEXT NOT NULL,
                    attempted_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_login_attempts_window
                ON login_attempts (dimension, dimension_key, attempted_at)
                """
            )
            return connection
        except (OSError, sqlite3.Error, ValueError) as error:
            if connection is not None:
                connection.close()
            raise LoginRateLimitStoreUnavailable from error

    def reserve_attempt(self, personnel_id: str, source_address: str) -> int | None:
        """Record an attempt or return seconds until the applicable limit clears."""
        now = time.time()
        keys = (
            ("personnel", self._digest(personnel_id.strip().casefold()), PERSONNEL_ATTEMPT_LIMIT),
            ("source", self._digest(source_address), SOURCE_ATTEMPT_LIMIT),
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM login_attempts WHERE attempted_at <= ?",
                (now - WINDOW_SECONDS,),
            )

            retry_after = 0
            for dimension, key, limit in keys:
                count = connection.execute(
                    """SELECT COUNT(*) FROM login_attempts
                       WHERE dimension = ? AND dimension_key = ?""",
                    (dimension, key),
                ).fetchone()[0]
                if count >= limit:
                    offset = count - limit
                    row = connection.execute(
                        """SELECT attempted_at FROM login_attempts
                           WHERE dimension = ? AND dimension_key = ?
                           ORDER BY attempted_at LIMIT 1 OFFSET ?""",
                        (dimension, key, offset),
                    ).fetchone()
                    if row is not None:
                        retry_after = max(
                            retry_after,
                            math.ceil(row[0] + WINDOW_SECONDS - now),
                        )

            if retry_after > 0:
                connection.commit()
                return retry_after

            connection.executemany(
                """INSERT INTO login_attempts (dimension, dimension_key, attempted_at)
                   VALUES (?, ?, ?)""",
                [(dimension, key, now) for dimension, key, _ in keys],
            )
            connection.commit()
            return None
        except sqlite3.Error as error:
            connection.rollback()
            raise LoginRateLimitStoreUnavailable from error
        finally:
            connection.close()

    def clear_personnel_attempts(self, personnel_id: str) -> None:
        """Clear the successful user's account bucket, retaining the source bucket."""
        key = self._digest(personnel_id.strip().casefold())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM login_attempts WHERE dimension = 'personnel' AND dimension_key = ?",
                (key,),
            )
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise LoginRateLimitStoreUnavailable from error
        finally:
            connection.close()
