import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.models.models import User
from app.security.authentication import _DUMMY_PASSWORD_HASH, authenticate_user
from app.security.passwords import hash_password, verify_password


class PasswordVerificationTests(unittest.TestCase):
    def test_hash_is_bcrypt_and_correct_password_verifies(self):
        password_hash = hash_password("correct horse battery staple")

        self.assertTrue(password_hash.startswith(("$2a$", "$2b$", "$2y$")))
        self.assertTrue(verify_password("correct horse battery staple", password_hash))

    def test_incorrect_password_does_not_verify(self):
        password_hash = hash_password("correct horse battery staple")

        self.assertFalse(verify_password("incorrect password", password_hash))

    def test_password_over_bcrypt_byte_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            hash_password("é" * 37)  # 74 UTF-8 bytes


class AuthenticateUserTests(unittest.TestCase):
    def setUp(self):
        self.db = Mock()
        self.query = self.db.query.return_value
        self.query.filter.return_value = self.query

    def set_user_result(self, user):
        self.query.first.return_value = user

    def test_correct_password_returns_active_user(self):
        password_hash = hash_password("correct password")
        user = SimpleNamespace(
            personnel_id="CTD-12345678",
            account_status="ACTIVE",
            password_hash=password_hash,
        )
        self.set_user_result(user)

        result = authenticate_user(self.db, user.personnel_id, "correct password")

        self.assertIs(result, user)
        self.db.query.assert_called_once_with(User)

    def test_incorrect_password_returns_none(self):
        user = SimpleNamespace(
            personnel_id="CTD-12345678",
            account_status="ACTIVE",
            password_hash=hash_password("correct password"),
        )
        self.set_user_result(user)

        self.assertIsNone(
            authenticate_user(self.db, user.personnel_id, "incorrect password")
        )

    def test_missing_user_returns_none(self):
        self.set_user_result(None)

        with patch("app.security.authentication.verify_password", return_value=False) as verify:
            self.assertIsNone(authenticate_user(self.db, "CTD-00000000", "password"))
        verify.assert_called_once()

    def test_passwordless_user_runs_dummy_bcrypt_verification(self):
        self.set_user_result(SimpleNamespace(
            personnel_id="CTD-12345678",
            account_status="ACTIVE",
            password_hash=None,
        ))

        with patch("app.security.authentication.verify_password", return_value=False) as verify:
            self.assertIsNone(
                authenticate_user(self.db, "CTD-12345678", "incorrect password")
            )
        verify.assert_called_once()

    def test_inactive_account_returns_none(self):
        user = SimpleNamespace(
            personnel_id="CTD-12345678",
            account_status="DISABLED",
            password_hash=hash_password("correct password"),
        )
        self.set_user_result(user)

        with patch("app.security.authentication.verify_password", return_value=True) as verify:
            self.assertIsNone(
                authenticate_user(self.db, user.personnel_id, "correct password")
            )
        verify.assert_called_once_with("correct password", _DUMMY_PASSWORD_HASH)

    def test_missing_password_hash_returns_none(self):
        user = SimpleNamespace(
            personnel_id="CTD-12345678",
            account_status="ACTIVE",
            password_hash=None,
        )
        self.set_user_result(user)

        self.assertIsNone(
            authenticate_user(self.db, user.personnel_id, "correct password")
        )


if __name__ == "__main__":
    unittest.main()
