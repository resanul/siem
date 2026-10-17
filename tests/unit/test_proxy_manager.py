import os
import unittest
import backend.app.services.proxy_manager as pm

class TestProxyManager(unittest.TestCase):
    def test_load_and_save_proxy_config(self):
        initial = pm.load_proxy_config()
        self.assertIn("enabled", initial)
        self.assertIn("http_proxy", initial)
        self.assertIn("no_proxy", initial)

        updated = pm.save_proxy_config({
            "enabled": True,
            "http_proxy": "http://172.31.105.10:3128",
            "https_proxy": "http://172.31.105.10:3128",
            "no_proxy": "localhost,127.0.0.1,10.0.0.0/8"
        })
        self.assertTrue(updated["enabled"])
        self.assertEqual(updated["http_proxy"], "http://172.31.105.10:3128")
        self.assertEqual(updated["status"], "ACTIVE")

        # Verify environment variables applied
        self.assertEqual(os.environ.get("HTTP_PROXY"), "http://172.31.105.10:3128")
        self.assertEqual(os.environ.get("HTTPS_PROXY"), "http://172.31.105.10:3128")

        # Revert back to original
        pm.save_proxy_config(initial)

    def test_empty_proxy_url_rejection(self):
        res = pm.test_proxy_connection("")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "error")
        self.assertIn("empty", res["message"])
