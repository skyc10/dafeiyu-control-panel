import io
import unittest
import urllib.error
from unittest.mock import patch
import server


PLUGIN = {"id": "companion_memory", "name": "陪伴记忆管理", "auth": "dsh",
          "port": 18080, "container": "fish-bot", "path": "/api/qq-companion-memory/v1/page"}
COOKIE = "dsh-auth-test=opaque; Path=/; HttpOnly; SameSite=Strict"


class PluginEntryTests(unittest.TestCase):
    def resolve(self, plugin=PLUGIN, cookie=COOKIE, status=303):
        response = urllib.error.HTTPError("http://127.0.0.1:18080/", status, "redirect",
                                          {"Set-Cookie": cookie}, io.BytesIO())
        with patch.object(server, "plugin_container_running", return_value=True), \
             patch.object(server, "port_open", return_value=True), \
             patch.object(server, "read_dsh_url", return_value=("http://127.0.0.1:18080/?token=current-secret", "ok")), \
             patch.object(server.urllib.request.OpenerDirector, "open", side_effect=response):
            return server.resolve_dsh_plugin(plugin)

    def test_cookie_exchanged_without_token_in_target_url(self):
        url, note, cookie = self.resolve()
        self.assertEqual(url, "http://127.0.0.1:18080/api/qq-companion-memory/v1/page")
        self.assertNotIn("secret", url + note)
        self.assertEqual(cookie, COOKIE)

    def test_wrong_port_container_and_external_path_rejected(self):
        for field, value in [("port", 19000), ("container", "other"), ("path", "//evil.example/")]:
            self.assertIsNone(self.resolve({**PLUGIN, field: value})[0])

    def test_bad_cookie_or_auth_failure_has_no_target(self):
        for cookie, status in [("", 303), (COOKIE, 401),
                               (COOKIE + "; Domain=evil.example", 303),
                               ("other=opaque; Path=/; HttpOnly", 303)]:
            self.assertIsNone(self.resolve(cookie=cookie, status=status)[0])

    def test_stopped_dsh_does_not_attempt_login(self):
        with patch.object(server, "plugin_container_running", return_value=False), \
             patch.object(server, "read_dsh_url") as read:
            self.assertIsNone(server.resolve_dsh_plugin(PLUGIN)[0])
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
