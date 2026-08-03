import tempfile
import unittest
from pathlib import Path

import app as ztp


class BrowserAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_dev = ztp.DEV_MODE
        self.old_auth = ztp.ADMIN_AUTH_JSON
        ztp.DEV_MODE = False
        ztp.ADMIN_AUTH_JSON = Path(self.temp.name) / "admin_auth.json"
        ztp._save_admin("operator", "correct-password")
        ztp.app.config.update(TESTING=True)
        self.client = ztp.app.test_client()

    def tearDown(self):
        ztp.DEV_MODE = self.old_dev
        ztp.ADMIN_AUTH_JSON = self.old_auth
        self.temp.cleanup()

    def test_browser_get_redirects_to_login(self):
        response = self.client.get("/?view=settings")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login?next=", response.headers["Location"])

    def test_login_creates_session_and_logout_clears_it(self):
        response = self.client.post("/login", data={
            "username": "operator", "password": "correct-password",
            "next": "/?view=settings",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/?view=settings")
        self.assertEqual(self.client.get("/?view=settings").status_code, 200)
        self.client.post("/logout")
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_api_keeps_basic_auth_challenge(self):
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Basic", response.headers["WWW-Authenticate"])

    def test_login_rejects_external_next_url(self):
        response = self.client.post("/login", data={
            "username": "operator", "password": "correct-password",
            "next": "https://example.invalid/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/?view=overview")


if __name__ == "__main__":
    unittest.main()
