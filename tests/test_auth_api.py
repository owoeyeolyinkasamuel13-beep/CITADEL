import base64
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.models.models import User
from app.routes.auth import login
from app.routes.records import test_record_access
from app.schemas.auth import LoginRequest
from app.security.tokens import (
    JWT_ALGORITHM,
    TokenConfigurationError,
    _get_secret_key,
    create_access_token,
    get_current_user,
)


TEST_SECRET_BYTES = b"test-only-secret-key-material-32bytes!"
TEST_SECRET = base64.urlsafe_b64encode(TEST_SECRET_BYTES).decode("ascii").rstrip("=")


def credentials(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class TokenConfigurationTests(unittest.TestCase):
    def test_missing_signing_key_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(TokenConfigurationError):
                _get_secret_key()

    def test_weak_signing_key_fails_closed(self):
        for key in ("too-short", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"):
            with self.subTest(key_length=len(key)):
                with patch.dict(os.environ, {"JWT_SECRET_KEY": key}, clear=True):
                    with self.assertRaises(TokenConfigurationError):
                        _get_secret_key()

    def test_token_expiration_configuration_must_be_positive_integer(self):
        for value in ("0", "-1", "61", "one"):
            with self.subTest(value=value):
                with patch.dict(
                    os.environ,
                    {"JWT_SECRET_KEY": TEST_SECRET,
                     "ACCESS_TOKEN_EXPIRE_MINUTES": value},
                    clear=True,
                ):
                    with self.assertRaises(TokenConfigurationError):
                        create_access_token(5)


class LoginApiTests(unittest.TestCase):
    def setUp(self):
        self.db = Mock()
        self.query = self.db.query.return_value
        self.query.filter.return_value = self.query
        self.http_request = SimpleNamespace(
            client=SimpleNamespace(host="192.0.2.10")
        )
        self.rate_limiter = Mock()
        self.rate_limiter.reserve_attempt.return_value = None
        self.rate_limiter_patcher = patch(
            "app.routes.auth.get_login_rate_limiter",
            return_value=self.rate_limiter,
        )
        self.rate_limiter_patcher.start()
        self.request = LoginRequest(
            personnel_id="CTD-12345678",
            password="correct password",
        )

    def tearDown(self):
        self.rate_limiter_patcher.stop()

    @patch("app.routes.auth.authenticate_user")
    def test_successful_login_returns_only_access_token_fields(self, authenticate):
        authenticate.return_value = SimpleNamespace(user_id=42, mfa_enabled=False)
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            response = login(self.request, self.http_request, self.db)

        self.assertEqual(response.token_type, "bearer")
        self.assertEqual(response.expires_in, 15 * 60)
        self.assertNotIn("password", response.model_dump())
        claims = jwt.decode(
            response.access_token,
            TEST_SECRET_BYTES,
            algorithms=[JWT_ALGORITHM],
        )
        self.assertEqual(claims["sub"], "42")
        self.assertEqual(claims["type"], "access")

    @patch("app.routes.auth.authenticate_user", return_value=None)
    def test_incorrect_credentials_return_generic_401_with_bearer_challenge(
        self, authenticate
    ):
        with self.assertRaises(HTTPException) as raised:
            login(self.request, self.http_request, self.db)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.headers, {"WWW-Authenticate": "Bearer"})
        self.assertEqual(raised.exception.detail, "Invalid personnel ID or password")

    @patch("app.routes.auth.authenticate_user", return_value=None)
    def test_inactive_account_has_same_login_error(self, authenticate):
        with self.assertRaises(HTTPException) as raised:
            login(self.request, self.http_request, self.db)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.headers, {"WWW-Authenticate": "Bearer"})

    @patch("app.routes.auth.authenticate_user")
    def test_missing_or_weak_signing_key_does_not_issue_token(self, authenticate):
        authenticate.return_value = SimpleNamespace(user_id=42, mfa_enabled=False)
        for key in (None, "weak"):
            with self.subTest(key="missing" if key is None else "weak"):
                env = {} if key is None else {"JWT_SECRET_KEY": key}
                with patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(HTTPException) as raised:
                        login(self.request, self.http_request, self.db)
                self.assertEqual(raised.exception.status_code, 503)

    @patch("app.routes.auth.create_access_token")
    @patch("app.routes.auth.authenticate_user")
    def test_mfa_enabled_account_cannot_receive_password_only_token(
        self, authenticate, create_token
    ):
        authenticate.return_value = SimpleNamespace(user_id=42, mfa_enabled=True)

        with self.assertRaises(HTTPException) as raised:
            login(self.request, self.http_request, self.db)

        self.assertEqual(raised.exception.status_code, 403)
        self.assertIn("Multi-factor", raised.exception.detail)
        create_token.assert_not_called()

    @patch("app.routes.auth.authenticate_user")
    def test_caller_cannot_supply_mfa_status_to_password_login(self, authenticate):
        authenticate.return_value = SimpleNamespace(user_id=42, mfa_enabled=False)
        request = LoginRequest.model_validate({
            "personnel_id": "CTD-12345678",
            "password": "correct password",
            "authentication_method": "mfa",
        })

        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            response = login(request, self.http_request, self.db)

        claims = jwt.decode(
            response.access_token,
            TEST_SECRET_BYTES,
            algorithms=[JWT_ALGORITHM],
        )
        self.assertEqual(claims["amr"], ["pwd"])

    def test_unknown_inactive_and_passwordless_accounts_share_login_failure(self):
        inactive = SimpleNamespace(
            account_status="DISABLED",
            password_hash="stored-but-not-used",
        )
        passwordless = SimpleNamespace(
            account_status="ACTIVE",
            password_hash=None,
        )
        self.query.first.side_effect = [None, inactive, passwordless]
        responses = []

        with patch("app.security.authentication.verify_password", return_value=False) as verify:
            for personnel_id in ("CTD-UNKNOWN", "CTD-INACTIVE", "CTD-EMPTY"):
                with self.subTest(personnel_id=personnel_id):
                    request = LoginRequest(
                        personnel_id=personnel_id,
                        password="wrong password",
                    )
                    with self.assertRaises(HTTPException) as raised:
                        login(request, self.http_request, self.db)
                    responses.append((
                        raised.exception.status_code,
                        raised.exception.detail,
                        raised.exception.headers,
                    ))

        self.assertEqual(responses[0], responses[1])
        self.assertEqual(responses[1], responses[2])
        self.assertEqual(verify.call_count, 3)


class AuthenticatedUserTests(unittest.TestCase):
    def setUp(self):
        self.db = Mock()
        self.query = self.db.query.return_value
        self.query.filter.return_value = self.query
        self.active_user = SimpleNamespace(
            user_id=42,
            account_status="ACTIVE",
            mfa_enabled=False,
        )

    def validate(self, token):
        return get_current_user(credentials(token), self.db)

    def assert_unauthorized(self, token):
        with self.assertRaises(HTTPException) as raised:
            self.validate(token)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.headers, {"WWW-Authenticate": "Bearer"})

    def signed_token(self, claims, secret=TEST_SECRET_BYTES, algorithm=JWT_ALGORITHM):
        return jwt.encode(claims, secret, algorithm=algorithm)

    def test_missing_and_malformed_tokens_return_401_with_challenge(self):
        with self.assertRaises(HTTPException) as raised:
            get_current_user(None, self.db)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.headers, {"WWW-Authenticate": "Bearer"})
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized("not.a.jwt")

    def test_incorrectly_signed_and_wrong_algorithm_tokens_are_rejected(self):
        now = datetime.now(timezone.utc)
        claims = {"sub": "42", "iat": now, "exp": now + timedelta(minutes=5),
                  "type": "access"}
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized(self.signed_token(claims, secret=b"x" * 40))
            self.assert_unauthorized(self.signed_token(claims, algorithm="HS384"))

    def test_expired_token_is_rejected(self):
        now = datetime.now(timezone.utc)
        token = self.signed_token({
            "sub": "42", "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=1), "type": "access",
        })
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized(token)

    def test_token_lifetime_over_sixty_minutes_is_rejected(self):
        now = datetime.now(timezone.utc)
        token = self.signed_token({
            "sub": "42",
            "iat": now,
            "exp": now + timedelta(minutes=61),
            "type": "access",
        })
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized(token)

    def test_future_issued_at_beyond_clock_skew_is_rejected(self):
        now = datetime.now(timezone.utc)
        token = self.signed_token({
            "sub": "42",
            "iat": now + timedelta(seconds=31),
            "exp": now + timedelta(minutes=5),
            "type": "access",
        })
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized(token)

    def test_effective_remaining_lifetime_cannot_exceed_sixty_minutes(self):
        now = datetime.now(timezone.utc)
        token = self.signed_token({
            "sub": "42",
            "iat": now + timedelta(seconds=10),
            "exp": now + timedelta(seconds=3601),
            "type": "access",
        })
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            self.assert_unauthorized(token)

    def test_missing_malformed_or_invalid_subject_is_rejected(self):
        now = datetime.now(timezone.utc)
        expiration = now + timedelta(minutes=5)
        claims_list = (
            {"exp": expiration, "type": "access"},
            {"sub": "abc", "exp": expiration, "type": "access"},
            {"sub": "0", "exp": expiration, "type": "access"},
            {"sub": "042", "exp": expiration, "type": "access"},
            {"sub": "42", "exp": expiration, "type": "refresh"},
        )
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            for claims in claims_list:
                with self.subTest(claims=claims):
                    self.assert_unauthorized(self.signed_token(claims))

    def test_active_user_is_loaded_from_database_by_token_subject(self):
        self.query.first.return_value = self.active_user
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            token, _ = create_access_token(42)
            result = self.validate(token)
        self.assertIs(result, self.active_user)
        self.db.query.assert_called_with(User)

    def test_password_token_is_rejected_after_account_mfa_is_enabled(self):
        self.query.first.return_value = self.active_user
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            token, _ = create_access_token(42)

            self.assertIs(self.validate(token), self.active_user)
            self.active_user.mfa_enabled = True
            self.assert_unauthorized(token)

    def test_mfa_verified_token_works_for_mfa_enabled_account(self):
        self.active_user.mfa_enabled = True
        self.query.first.return_value = self.active_user

        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            token, _ = create_access_token(42, authentication_method="mfa")
            result = self.validate(token)

        self.assertIs(result, self.active_user)

    def test_legacy_session_for_mfa_disabled_account_remains_valid(self):
        now = datetime.now(timezone.utc)
        token = self.signed_token({
            "sub": "42",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        })
        self.query.first.return_value = self.active_user

        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            result = self.validate(token)

        self.assertIs(result, self.active_user)

    def test_account_deactivated_after_issuance_is_rejected(self):
        self.query.first.return_value = SimpleNamespace(
            user_id=42,
            account_status="DISABLED",
        )
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            token, _ = create_access_token(42)
            self.assert_unauthorized(token)

    def test_nonexistent_user_is_rejected(self):
        self.query.first.return_value = None
        with patch.dict(os.environ, {"JWT_SECRET_KEY": TEST_SECRET}, clear=True):
            token, _ = create_access_token(42)
            self.assert_unauthorized(token)


class ProtectedRecordRouteTests(unittest.TestCase):
    @patch("app.routes.records.can_access_record", return_value=True)
    @patch("app.routes.records.has_permission", return_value=True)
    def test_authorization_checks_use_verified_user_id(self, has_permission, can_access):
        current_user = SimpleNamespace(user_id=42)
        record = SimpleNamespace(
            record_code="REC-1",
            classification_status="APPROVED",
            record_content="classified",
            title="Title",
            description="Description",
        )
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = record

        result = test_record_access("REC-1", current_user, db)

        has_permission.assert_called_once_with(db, 42, "VIEW_RECORDS")
        can_access.assert_called_once_with(db, 42, record)
        self.assertEqual(result["access"], "GRANTED")

    @patch("app.routes.records.can_access_record", return_value=True)
    @patch("app.routes.records.has_permission", return_value=False)
    def test_existing_permission_check_still_denies_access(self, has_permission, can_access):
        current_user = SimpleNamespace(user_id=42)
        record = SimpleNamespace(record_code="REC-1")
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = record

        result = test_record_access("REC-1", current_user, db)

        self.assertEqual(result.status_code, 403)
        self.assertEqual(
            json.loads(result.body),
            {"access": "DENIED", "reason": "Insufficient authorization"},
        )
        can_access.assert_not_called()
        db.query.assert_not_called()

    @patch("app.routes.records.can_access_record", return_value=False)
    @patch("app.routes.records.has_permission", return_value=True)
    def test_existing_clearance_check_still_denies_access(self, has_permission, can_access):
        current_user = SimpleNamespace(user_id=42)
        record = SimpleNamespace(record_code="REC-1")
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = record

        result = test_record_access("REC-1", current_user, db)

        self.assertEqual(result.status_code, 404)
        self.assertEqual(
            json.loads(result.body),
            {"access": "DENIED", "reason": "Record not found"},
        )
        can_access.assert_called_once_with(db, 42, record)


if __name__ == "__main__":
    unittest.main()
