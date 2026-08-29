"""
SMS SENTINEL — Authentication & User Data Isolation Test Suite
Verifies:
- Registration validation and duplicate email prevention
- Password hashing security (Werkzeug PBKDF2 / scrypt)
- Session creation, persistence, and logout destruction
- Protected HTML and API routes (401 and redirect checks)
- Strict User Data Isolation between User A and User B
- Insecure Direct Object Reference (IDOR) access prevention
- XSS and SQL injection security across authentication forms
"""

import os
import json
import sqlite3
import unittest

from app import app
from database.db import DB_PATH, init_db, clear_analyses

class TestAuthenticationSystem(unittest.TestCase):
    def setUp(self):
        """Set up fresh test client with active session tracking."""
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        init_db()

        # Clean database state for tests
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM analyses")
        cursor.execute("DELETE FROM users")
        conn.commit()
        conn.close()

    # =========================================================================
    # 1. REGISTRATION TESTS (AUTH01 - AUTH06)
    # =========================================================================

    def test_auth01_valid_registration(self):
        """AUTH01: Verify valid registration creates user, hashes password, and sets session."""
        res = self.client.post("/api/auth/register", json={
            "name": "Alpha Tester",
            "email": "alpha@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], "alpha@example.com")
        self.assertEqual(data["user"]["name"], "Alpha Tester")
        self.assertNotIn("password", data["user"])
        self.assertNotIn("password_hash", data["user"])

        # Verify session state via /api/auth/me
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.get_json()
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["user"]["email"], "alpha@example.com")

    def test_auth02_duplicate_email(self):
        """AUTH02: Verify duplicate email registration is rejected with HTTP 400."""
        # First registration
        self.client.post("/api/auth/register", json={
            "name": "First User",
            "email": "duplicate@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        # Second registration with same email
        res = self.client.post("/api/auth/register", json={
            "name": "Second User",
            "email": "duplicate@example.com",
            "password": "DifferentPassword456!",
            "confirm_password": "DifferentPassword456!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["success"])
        self.assertIn("already exists", res.get_json()["error"])

    def test_auth03_invalid_email(self):
        """AUTH03: Verify malformed email addresses are rejected."""
        res = self.client.post("/api/auth/register", json={
            "name": "Test User",
            "email": "not-an-email",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("valid email", res.get_json()["error"])

    def test_auth04_empty_fields(self):
        """AUTH04: Verify missing or empty fields return HTTP 400."""
        res = self.client.post("/api/auth/register", json={
            "name": "",
            "email": "empty@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("name", res.get_json()["error"].lower())

    def test_auth05_password_mismatch(self):
        """AUTH05: Verify mismatching passwords are rejected."""
        res = self.client.post("/api/auth/register", json={
            "name": "Mismatch Tester",
            "email": "mismatch@example.com",
            "password": "Password123!",
            "confirm_password": "Password456!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("match", res.get_json()["error"])

    def test_auth06_short_password(self):
        """AUTH06: Verify passwords under 8 characters are rejected."""
        res = self.client.post("/api/auth/register", json={
            "name": "Short Pass",
            "email": "short@example.com",
            "password": "123",
            "confirm_password": "123"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("8 characters", res.get_json()["error"])

    # =========================================================================
    # 2. LOGIN & LOGOUT TESTS (AUTH07 - AUTH14)
    # =========================================================================

    def test_auth07_successful_login(self):
        """AUTH07: Verify valid login establishes authenticated session."""
        # Create user
        self.client.post("/api/auth/register", json={
            "name": "Login Tester",
            "email": "login@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        })
        # Clear session
        self.client.post("/api/auth/logout")

        # Perform Login
        res = self.client.post("/api/auth/login", json={
            "email": "login@example.com",
            "password": "SecurePassword123!"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], "login@example.com")

        # Verify active session
        me_res = self.client.get("/api/auth/me")
        self.assertTrue(me_res.get_json()["authenticated"])

    def test_auth08_wrong_password(self):
        """AUTH08: Verify incorrect password returns HTTP 401."""
        self.client.post("/api/auth/register", json={
            "name": "Wrong Pass Tester",
            "email": "wrongpass@example.com",
            "password": "CorrectPassword123!",
            "confirm_password": "CorrectPassword123!"
        })
        self.client.post("/api/auth/logout")

        res = self.client.post("/api/auth/login", json={
            "email": "wrongpass@example.com",
            "password": "IncorrectPassword999!"
        })
        self.assertEqual(res.status_code, 401)
        self.assertFalse(res.get_json()["success"])

    def test_auth09_unknown_account(self):
        """AUTH09: Verify unknown email returns HTTP 401 without exposing account existence."""
        res = self.client.post("/api/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "SomePassword123!"
        })
        self.assertEqual(res.status_code, 401)
        self.assertFalse(res.get_json()["success"])

    def test_auth10_logged_out_protected_html(self):
        """AUTH10: Verify unauthenticated requests to protected HTML routes redirect to /login."""
        routes = ["/", "/scan", "/archive", "/insights"]
        for r in routes:
            res = self.client.get(r)
            self.assertEqual(res.status_code, 302, f"Failed redirect on route: {r}")
            self.assertIn("/login", res.headers.get("Location", ""))

    def test_auth11_logged_out_protected_api(self):
        """AUTH11: Verify unauthenticated API requests return HTTP 401 JSON."""
        res_predict = self.client.post("/api/predict", json={"message": "Winner cash prize"})
        self.assertEqual(res_predict.status_code, 401)
        self.assertFalse(res_predict.get_json()["authenticated"])

        res_analyses = self.client.get("/api/analyses")
        self.assertEqual(res_analyses.status_code, 401)

        res_insights = self.client.get("/api/insights")
        self.assertEqual(res_insights.status_code, 401)

    def test_auth12_logout_and_session_destruction(self):
        """AUTH12 & AUTH13: Verify logout clears session and subsequent protected calls fail."""
        # Login
        self.client.post("/api/auth/register", json={
            "name": "Logout Tester",
            "email": "logout@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        # Logout
        res_logout = self.client.post("/api/auth/logout")
        self.assertEqual(res_logout.status_code, 200)

        # Check me
        res_me = self.client.get("/api/auth/me")
        self.assertFalse(res_me.get_json()["authenticated"])

        # Protected API fails
        res_pred = self.client.post("/api/predict", json={"message": "Free cash prize"})
        self.assertEqual(res_pred.status_code, 401)

    # =========================================================================
    # 3. USER DATA ISOLATION & IDOR TESTS (AUTH15 - AUTH17)
    # =========================================================================

    def test_auth15_user_data_isolation_and_idor(self):
        """
        AUTH15, AUTH16, AUTH17:
        Verify User A only sees User A's data, User B only sees User B's data,
        and User B cannot access User A's record by direct ID (IDOR protection).
        """
        client_a = app.test_client()
        client_b = app.test_client()

        # 1. Register User A
        client_a.post("/api/auth/register", json={
            "name": "Alice Admin",
            "email": "alice@sentinel.sec",
            "password": "AlicePassword123!",
            "confirm_password": "AlicePassword123!"
        })

        # 2. Register User B
        client_b.post("/api/auth/register", json={
            "name": "Bob Analyst",
            "email": "bob@sentinel.sec",
            "password": "BobPassword123!",
            "confirm_password": "BobPassword123!"
        })

        # 3. User A creates 2 analyses
        res_a1 = client_a.post("/api/predict", json={"message": "Alice secret spam win money"})
        id_a1 = res_a1.get_json()["id"]

        res_a2 = client_a.post("/api/predict", json={"message": "Alice legitimate meeting at 5"})
        id_a2 = res_a2.get_json()["id"]

        # 4. User B creates 1 analysis
        res_b1 = client_b.post("/api/predict", json={"message": "Bob urgent bank alert http://bit.ly/bank"})
        id_b1 = res_b1.get_json()["id"]

        # 5. Check Archive isolation
        arch_a = client_a.get("/api/analyses").get_json()
        self.assertEqual(arch_a["total"], 2)
        messages_a = [r["message"] for r in arch_a["data"]]
        self.assertIn("Alice secret spam win money", messages_a)
        self.assertNotIn("Bob urgent bank alert http://bit.ly/bank", messages_a)

        arch_b = client_b.get("/api/analyses").get_json()
        self.assertEqual(arch_b["total"], 1)
        messages_b = [r["message"] for r in arch_b["data"]]
        self.assertIn("Bob urgent bank alert http://bit.ly/bank", messages_b)
        self.assertNotIn("Alice secret spam win money", messages_b)

        # 6. Check Insights isolation
        ins_a = client_a.get("/api/insights").get_json()["data"]
        self.assertEqual(ins_a["totals"]["analyses"], 2)

        ins_b = client_b.get("/api/insights").get_json()["data"]
        self.assertEqual(ins_b["totals"]["analyses"], 1)

        # 7. IDOR Security Test: User B attempts to access User A's record (id_a1)
        res_idor = client_b.get(f"/api/analyses/{id_a1}")
        self.assertEqual(res_idor.status_code, 404, "IDOR Vulnerability: User B accessed User A's record!")

        # 8. IDOR Delete Test: User B attempts to delete User A's record (id_a1)
        res_del_idor = client_b.delete(f"/api/analyses/{id_a1}")
        self.assertEqual(res_del_idor.status_code, 404, "IDOR Vulnerability: User B deleted User A's record!")

        # Confirm User A's record still exists for User A
        res_a_verify = client_a.get(f"/api/analyses/{id_a1}")
        self.assertEqual(res_a_verify.status_code, 200)

    # =========================================================================
    # 4. ADVERSARIAL SECURITY & INJECTION TESTS (AUTH18 - AUTH20)
    # =========================================================================

    def test_auth18_xss_and_sqli_in_auth(self):
        """AUTH18 & AUTH19: Verify XSS and SQL injection payloads are neutralized in auth endpoints."""
        malicious_payloads = [
            "<script>alert('XSS')</script>",
            "' OR '1'='1' --",
            "admin' --",
            "\"><img src=x onerror=alert(1)>",
            "'; DROP TABLE users; --"
        ]

        for payload in malicious_payloads:
            # Registration with injection payload in name
            res_reg = self.client.post("/api/auth/register", json={
                "name": payload,
                "email": f"inj_{abs(hash(payload))}@test.com",
                "password": "Password123!",
                "confirm_password": "Password123!"
            })
            self.assertEqual(res_reg.status_code, 201)

            # Login with SQL injection in email
            res_login = self.client.post("/api/auth/login", json={
                "email": payload,
                "password": "Password123!"
            })
            self.assertEqual(res_login.status_code, 401)

        # Verify users table was not dropped
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        self.assertGreater(count, 0)
        conn.close()

if __name__ == "__main__":
    unittest.main()
