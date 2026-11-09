import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import ANY, Mock, patch

from app.database.connection import get_db
from app.security.tokens import get_current_user
from main import app


async def _request(method, path, body=None):
    raw_body = b"" if body is None else json.dumps(body).encode("utf-8")
    messages = [{"type": "http.request", "body": raw_body, "more_body": False}]
    response_messages = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        response_messages.append(message)

    await asyncio.wait_for(
        app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": path,
                "raw_path": path.encode("ascii"),
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
                "client": ("testclient", 123),
                "server": ("testserver", 80),
            },
            receive,
            send,
        ),
        timeout=5,
    )
    start = response_messages[0]
    content = b"".join(
        message.get("body", b"")
        for message in response_messages
        if message["type"] == "http.response.body"
    )
    return SimpleNamespace(
        status_code=start["status"],
        headers={key.decode(): value.decode() for key, value in start["headers"]},
        text=content.decode("utf-8"),
        json=lambda: json.loads(content),
    )


class SecurityHttpTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides.clear()
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            user_id=7,
            account_status="ACTIVE",
            clearance_id=4,
        )
        app.dependency_overrides[get_db] = lambda: Mock()

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_login_validation_response_does_not_echo_password(self):
        response = asyncio.run(
            _request(
                "POST",
                "/auth/login",
                {"personnel_id": "CTD-1", "password": "secret-marker" * 12},
            )
        )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn("secret-marker", response.text)
        self.assertNotIn("input", response.json()["detail"][0])

    @patch("app.routes.users.has_permission", return_value=False)
    def test_user_list_rejects_authenticated_user_without_manage_permission(
        self, has_permission
    ):
        response = asyncio.run(_request("GET", "/users/"))

        self.assertEqual(response.status_code, 403)
        has_permission.assert_called_once_with(ANY, 7, "MANAGE_USERS")

    @patch("app.routes.users.has_permission", return_value=True)
    def test_user_list_returns_allowed_data_without_password_hash(self, has_permission):
        db = Mock()
        db.query.return_value.all.return_value = [
            SimpleNamespace(
                user_id=11,
                personnel_id="CTD-00000011",
                first_name="Test",
                last_name="User",
                email="test@example.invalid",
                role_id=2,
                department_id=3,
                clearance_id=4,
                account_status="ACTIVE",
                mfa_enabled=True,
            )
        ]
        app.dependency_overrides[get_db] = lambda: db

        response = asyncio.run(_request("GET", "/users/"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["user_id"], 11)
        self.assertNotIn("password_hash", response.json()[0])
        has_permission.assert_called_once_with(db, 7, "MANAGE_USERS")

    def test_users_endpoint_without_token_returns_bearer_challenge(self):
        app.dependency_overrides.pop(get_current_user)

        response = asyncio.run(_request("GET", "/users/"))

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")

    @patch("app.routes.auth.get_login_rate_limiter")
    @patch("app.routes.auth.authenticate_user")
    def test_login_throttle_returns_429_before_password_verification(
        self, authenticate, get_limiter
    ):
        get_limiter.return_value.reserve_attempt.return_value = 37

        response = asyncio.run(
            _request(
                "POST",
                "/auth/login",
                {"personnel_id": "CTD-12345678", "password": "incorrect password"},
            )
        )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "37")
        authenticate.assert_not_called()

    @patch("app.routes.records.has_permission", return_value=False)
    def test_record_lookup_without_permission_does_not_disclose_existence(
        self, has_permission
    ):
        db = Mock()
        app.dependency_overrides[get_db] = lambda: db

        existing = asyncio.run(_request("GET", "/records/REC-EXISTS/access"))
        missing = asyncio.run(_request("GET", "/records/REC-MISSING/access"))

        self.assertEqual(existing.status_code, 403)
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(existing.json(), missing.json())
        self.assertEqual(
            existing.json(),
            {"access": "DENIED", "reason": "Insufficient authorization"},
        )
        self.assertEqual(has_permission.call_count, 2)
        db.query.assert_not_called()

    @patch("app.routes.records.can_access_record", return_value=True)
    @patch("app.routes.records.has_permission", return_value=True)
    def test_record_access_granted_with_permission_and_sufficient_clearance(
        self, has_permission, can_access
    ):
        record = SimpleNamespace(
            record_code="REC-ALLOWED",
            title="Authorized title",
            description="Authorized description",
            record_content="Authorized content",
        )
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = record
        app.dependency_overrides[get_db] = lambda: db

        response = asyncio.run(_request("GET", "/records/REC-ALLOWED/access"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["access"], "GRANTED")
        self.assertEqual(response.json()["record_content"], "Authorized content")
        has_permission.assert_called_once_with(db, 7, "VIEW_RECORDS")
        can_access.assert_called_once_with(db, 7, record)

    @patch("app.routes.records.can_access_record", return_value=False)
    @patch("app.routes.records.has_permission", return_value=True)
    def test_insufficient_clearance_matches_nonexistent_record_response(
        self, has_permission, can_access
    ):
        db = Mock()
        db.query.return_value.filter.return_value.first.side_effect = [
            SimpleNamespace(
                record_code="REC-RESTRICTED",
                title="Restricted title",
                description="Restricted description",
                record_content="Restricted content",
                clearance_id=9,
            ),
            None,
        ]
        app.dependency_overrides[get_db] = lambda: db

        restricted = asyncio.run(
            _request("GET", "/records/REC-RESTRICTED/access")
        )
        missing = asyncio.run(_request("GET", "/records/REC-MISSING/access"))

        self.assertEqual(restricted.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(restricted.status_code, missing.status_code)
        self.assertEqual(restricted.json(), missing.json())
        self.assertEqual(
            restricted.json(),
            {"access": "DENIED", "reason": "Record not found"},
        )
        self.assertEqual(
            missing.json(),
            {"access": "DENIED", "reason": "Record not found"},
        )
        for sensitive_value in (
            "REC-RESTRICTED",
            "Restricted title",
            "Restricted description",
            "Restricted content",
        ):
            self.assertNotIn(sensitive_value, restricted.text)
        self.assertEqual(has_permission.call_count, 2)
        self.assertEqual(can_access.call_count, 1)

    @patch("app.routes.records.can_access_record", side_effect=[True, False])
    @patch("app.routes.records.has_permission", return_value=True)
    def test_record_list_only_returns_records_with_sufficient_clearance(
        self, has_permission, can_access
    ):
        permitted = SimpleNamespace(
            record_id=1,
            record_code="REC-1",
            title="Allowed",
            description=None,
            category_id=1,
            clearance_id=2,
            classification_status="APPROVED",
            created_by=7,
            classified_by=None,
            classified_at=None,
            status="ACTIVE",
        )
        withheld = SimpleNamespace(
            record_id=2,
            record_code="REC-2",
            title="Withheld",
            description=None,
            category_id=1,
            clearance_id=9,
            classification_status="APPROVED",
            created_by=7,
            classified_by=None,
            classified_at=None,
            status="ACTIVE",
        )
        db = Mock()
        db.query.return_value.filter.return_value.all.return_value = [permitted, withheld]
        app.dependency_overrides[get_db] = lambda: db

        response = asyncio.run(_request("GET", "/records/"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["record_code"] for item in response.json()], ["REC-1"])
        has_permission.assert_called_once_with(db, 7, "VIEW_RECORDS")
        self.assertEqual(can_access.call_count, 2)


if __name__ == "__main__":
    unittest.main()
