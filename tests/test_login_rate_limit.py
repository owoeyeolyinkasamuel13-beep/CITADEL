import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.security.login_rate_limit import (
    LoginRateLimitStoreUnavailable,
    SQLiteLoginRateLimiter,
)


class SQLiteLoginRateLimiterTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(
            dir=Path(__file__).resolve().parents[1],
            prefix=".test-login-rate-limit-",
        )
        self.limiter = SQLiteLoginRateLimiter(
            Path(self.temp_dir.name) / "login-attempts.sqlite3"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_personnel_limit_is_shared_across_source_addresses(self):
        for attempt in range(5):
            self.assertIsNone(
                self.limiter.reserve_attempt("CTD-123", f"192.0.2.{attempt + 1}")
            )

        retry_after = self.limiter.reserve_attempt("CTD-123", "198.51.100.1")

        self.assertIsNotNone(retry_after)
        self.assertGreater(retry_after, 0)

    def test_source_limit_applies_across_personnel_ids(self):
        with patch("app.security.login_rate_limit.SOURCE_ATTEMPT_LIMIT", 2):
            self.assertIsNone(self.limiter.reserve_attempt("CTD-1", "192.0.2.1"))
            self.assertIsNone(self.limiter.reserve_attempt("CTD-2", "192.0.2.1"))
            retry_after = self.limiter.reserve_attempt("CTD-3", "192.0.2.1")

        self.assertIsNotNone(retry_after)
        self.assertGreater(retry_after, 0)

    def test_successful_authentication_can_clear_only_personnel_bucket(self):
        for attempt in range(5):
            self.limiter.reserve_attempt("CTD-123", f"192.0.2.{attempt + 1}")

        self.limiter.clear_personnel_attempts("CTD-123")

        self.assertIsNone(self.limiter.reserve_attempt("CTD-123", "198.51.100.1"))

    def test_in_memory_and_production_local_stores_fail_closed(self):
        with self.assertRaises(LoginRateLimitStoreUnavailable):
            SQLiteLoginRateLimiter(":memory:")

        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(LoginRateLimitStoreUnavailable):
                SQLiteLoginRateLimiter.from_environment()

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(LoginRateLimitStoreUnavailable):
                SQLiteLoginRateLimiter.from_environment()


if __name__ == "__main__":
    unittest.main()
