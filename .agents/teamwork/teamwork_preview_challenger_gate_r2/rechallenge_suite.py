"""
Adversarial Re-Challenge and Gate Verification Suite (Iteration 2).
Empirical verification of backend event search robustness, input fuzzing,
GET vs POST contract parity, and extreme parameter handling.
"""

import sys
import unittest
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.security import create_access_token, UserRole


class TestIteration2GateVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Disable server exceptions bubbling up so we catch any 500s directly
        cls.client = TestClient(app, raise_server_exceptions=False)
        cls.analyst_token = create_access_token(
            data={"sub": "adversary_analyst", "role": UserRole.SECOPS_VIEWER.value}
        )
        cls.headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    # =========================================================================
    # 1. NON-SCALAR LIMIT VALUES (POST & GET) -> HTTP 422 (NEVER 500)
    # =========================================================================

    def test_non_scalar_limit_list(self):
        """Passing [10] as limit in POST must yield 422, never 500."""
        r = self.client.post("/api/v1/events/search", json={"limit": [10]}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_nested_dict(self):
        """Passing {'limit': 10} as limit in POST must yield 422, never 500."""
        r = self.client.post("/api/v1/events/search", json={"limit": {"limit": 10}}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_float(self):
        """Passing 3.14 as limit in POST must yield 422, never 500 or silent truncation."""
        r = self.client.post("/api/v1/events/search", json={"limit": 3.14}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_bool_true(self):
        """Passing True as limit in POST must yield 422, never coerced to 1."""
        r = self.client.post("/api/v1/events/search", json={"limit": True}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_bool_false(self):
        """Passing False as limit in POST must yield 422, never coerced to 0."""
        r = self.client.post("/api/v1/events/search", json={"limit": False}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_string_abc(self):
        """Passing 'abc' as limit in POST must yield 422, never 500."""
        r = self.client.post("/api/v1/events/search", json={"limit": "abc"}, headers=self.headers)
        self.assertEqual(r.status_code, 422, f"Expected 422, got {r.status_code}: {r.text}")

    def test_non_scalar_limit_fuzzing(self):
        """Fuzz non-scalar and invalid limit values across multiple unexpected types."""
        fuzz_cases = [
            [],
            [1, 2, 3],
            {},
            {"a": 1},
            [None],
            3.999,
            -0.5,
            "1.5",
            "NaN",
            "Infinity",
            "-Infinity",
            "0x10",
            "   ",
            "",
        ]
        for val in fuzz_cases:
            with self.subTest(val=val):
                r = self.client.post("/api/v1/events/search", json={"limit": val}, headers=self.headers)
                self.assertEqual(
                    r.status_code, 422,
                    f"Fuzz value {val!r} returned status {r.status_code} instead of 422: {r.text}"
                )

    # =========================================================================
    # 2. LARGE/EXTREME TIME_RANGE VALUES -> HTTP 200 (NEVER 500 OVERFLOWERROR)
    # =========================================================================

    def test_extreme_time_range_100_million_days_post(self):
        """Extreme 100,000,000d must succeed with HTTP 200, no OverflowError."""
        r = self.client.post("/api/v1/events/search", json={"time_range": "100000000d"}, headers=self.headers)
        self.assertEqual(r.status_code, 200, f"Got {r.status_code}: {r.text}")
        data = r.json()
        self.assertIn("events", data)
        self.assertIn("total_hits", data)

    def test_extreme_time_range_gigantic_integer_days_post(self):
        """C int overflow 9999999999999999999999999999999999999999999999999999d must return HTTP 200."""
        huge_val = "9" * 52 + "d"
        r = self.client.post("/api/v1/events/search", json={"time_range": huge_val}, headers=self.headers)
        self.assertEqual(r.status_code, 200, f"Got {r.status_code}: {r.text}")
        data = r.json()
        self.assertIn("events", data)

    def test_extreme_time_range_100_million_hours_post(self):
        """Extreme 100,000,000h must succeed with HTTP 200."""
        r = self.client.post("/api/v1/events/search", json={"time_range": "100000000h"}, headers=self.headers)
        self.assertEqual(r.status_code, 200, f"Got {r.status_code}: {r.text}")

    def test_extreme_time_range_extreme_units_post(self):
        """Extreme values across all supported time units (s, m, h, d)."""
        units = ["s", "m", "h", "d"]
        for u in units:
            with self.subTest(unit=u):
                val = f"500000000{u}"
                r = self.client.post("/api/v1/events/search", json={"time_range": val}, headers=self.headers)
                self.assertEqual(r.status_code, 200, f"Unit {u} failed with {r.status_code}: {r.text}")

    def test_extreme_time_range_get(self):
        """Extreme time_range on GET endpoint must also return HTTP 200, never 500."""
        params_to_test = [
            "100000000d",
            "9" * 40 + "d",
            "100000000h",
            "100000000m",
            "100000000s",
            "*",
            "all",
            "ALL",
            "7D",
            "24H",
        ]
        for tr in params_to_test:
            with self.subTest(tr=tr):
                r = self.client.get(f"/api/v1/events/search?time_range={tr}", headers=self.headers)
                self.assertEqual(r.status_code, 200, f"GET with time_range={tr} failed with {r.status_code}: {r.text}")
                data = r.json()
                self.assertIn("events", data)

    # =========================================================================
    # 3. GET VS POST CONTRACT PARITY ON LIMIT
    # =========================================================================

    def test_parity_limit_zero(self):
        """GET and POST must BOTH return HTTP 422 when limit=0."""
        r_get = self.client.get("/api/v1/events/search?limit=0", headers=self.headers)
        r_post = self.client.post("/api/v1/events/search", json={"limit": 0}, headers=self.headers)
        self.assertEqual(r_get.status_code, 422, f"GET limit=0 returned {r_get.status_code}")
        self.assertEqual(r_post.status_code, 422, f"POST limit=0 returned {r_post.status_code}")
        self.assertEqual(r_get.status_code, r_post.status_code, "Parity mismatch for limit=0")

    def test_parity_limit_negative(self):
        """GET and POST must BOTH return HTTP 422 when limit=-5."""
        r_get = self.client.get("/api/v1/events/search?limit=-5", headers=self.headers)
        r_post = self.client.post("/api/v1/events/search", json={"limit": -5}, headers=self.headers)
        self.assertEqual(r_get.status_code, 422, f"GET limit=-5 returned {r_get.status_code}")
        self.assertEqual(r_post.status_code, 422, f"POST limit=-5 returned {r_post.status_code}")
        self.assertEqual(r_get.status_code, r_post.status_code, "Parity mismatch for limit=-5")

    def test_parity_limit_exceeds_max(self):
        """GET and POST must BOTH return HTTP 422 when limit=201."""
        r_get = self.client.get("/api/v1/events/search?limit=201", headers=self.headers)
        r_post = self.client.post("/api/v1/events/search", json={"limit": 201}, headers=self.headers)
        self.assertEqual(r_get.status_code, 422, f"GET limit=201 returned {r_get.status_code}")
        self.assertEqual(r_post.status_code, 422, f"POST limit=201 returned {r_post.status_code}")
        self.assertEqual(r_get.status_code, r_post.status_code, "Parity mismatch for limit=201")

    def test_parity_valid_limits(self):
        """GET and POST must BOTH return HTTP 200 for valid boundary limits: 1, 50, 200."""
        for lim in [1, 50, 200]:
            with self.subTest(lim=lim):
                r_get = self.client.get(f"/api/v1/events/search?limit={lim}", headers=self.headers)
                r_post = self.client.post("/api/v1/events/search", json={"limit": lim}, headers=self.headers)
                self.assertEqual(r_get.status_code, 200, f"GET limit={lim} failed: {r_get.text}")
                self.assertEqual(r_post.status_code, 200, f"POST limit={lim} failed: {r_post.text}")
                self.assertLessEqual(len(r_get.json()["events"]), lim)
                self.assertLessEqual(len(r_post.json()["events"]), lim)

    def test_parity_invalid_string_limit(self):
        """GET and POST must BOTH return HTTP 422 for limit='abc'."""
        r_get = self.client.get("/api/v1/events/search?limit=abc", headers=self.headers)
        r_post = self.client.post("/api/v1/events/search", json={"limit": "abc"}, headers=self.headers)
        self.assertEqual(r_get.status_code, 422, f"GET limit='abc' returned {r_get.status_code}")
        self.assertEqual(r_post.status_code, 422, f"POST limit='abc' returned {r_post.status_code}")

    def test_parity_float_limit(self):
        """GET and POST must BOTH return HTTP 422 for limit=3.14."""
        r_get = self.client.get("/api/v1/events/search?limit=3.14", headers=self.headers)
        r_post = self.client.post("/api/v1/events/search", json={"limit": 3.14}, headers=self.headers)
        self.assertEqual(r_get.status_code, 422, f"GET limit=3.14 returned {r_get.status_code}")
        self.assertEqual(r_post.status_code, 422, f"POST limit=3.14 returned {r_post.status_code}")

    # =========================================================================
    # 4. ELASTICSEARCH INTERACTION INTEGRITY
    # =========================================================================

    @patch("urllib.request.urlopen")
    def test_elasticsearch_all_or_wildcard_time_range_format(self, mock_urlopen):
        """When time_range is 'all' or '*', Elasticsearch query body must not contain 'now-*' filter."""
        import json
        recorded_body = []

        def side_effect(req, *args, **kwargs):
            body_bytes = req.data
            if body_bytes:
                recorded_body.append(json.loads(body_bytes.decode("utf-8")))
            m = MagicMock()
            m.getcode.return_value = 200
            m.read.return_value = json.dumps({
                "took": 5,
                "hits": {"total": {"value": 0}, "hits": []}
            }).encode("utf-8")
            m.__enter__.return_value = m
            return m

        mock_urlopen.side_effect = side_effect

        for tr in ["all", "*", "ALL"]:
            del recorded_body[:]
            r = self.client.post("/api/v1/events/search", json={"time_range": tr}, headers=self.headers)
            self.assertEqual(r.status_code, 200)
            if recorded_body:
                filters = recorded_body[0].get("query", {}).get("bool", {}).get("filter", [])
                for f in filters:
                    self.assertNotIn("range", f, f"Elasticsearch filter unexpectedly had range for time_range={tr}")

    # =========================================================================
    # 5. RESPONSE SCHEMA & DATA INTEGRITY
    # =========================================================================

    def test_response_schema_completeness(self):
        """Verify full response schema compliance for both POST and GET."""
        for method in ["POST", "GET"]:
            if method == "POST":
                r = self.client.post("/api/v1/events/search", json={"query": "*", "limit": 10}, headers=self.headers)
            else:
                r = self.client.get("/api/v1/events/search?query=*&limit=10", headers=self.headers)

            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn("total_hits", data)
            self.assertIn("took_ms", data)
            self.assertIn("indices_searched", data)
            self.assertIn("events", data)
            self.assertIsInstance(data["events"], list)
            self.assertGreater(len(data["events"]), 0)

            evt = data["events"][0]
            required_fields = ["id", "timestamp", "index", "source_type", "host", "severity", "summary", "raw"]
            for field in required_fields:
                self.assertIn(field, evt, f"Missing field {field} in event item")


if __name__ == "__main__":
    unittest.main()
