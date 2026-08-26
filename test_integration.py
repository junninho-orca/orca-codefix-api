#!/usr/bin/env python3
"""End-to-end tests for the Cloud Function against a fake Orca API.

    python3 -m pip install -r requirements.txt
    python3 test_integration.py

Nothing here touches the real Orca API, spends an AI metering unit, or opens a
pull request — a local HTTP server stands in for api.orcasecurity.io. Run this
after changing main.py or orca_codefix.py, and after a fresh clone to confirm the
environment is sane before deploying.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import pathlib
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

SAMPLES = pathlib.Path(__file__).with_name("samples")

# What the real ai-core skill returns for a fixable SAST alert.
FIX = {
    "remediation_type": "code_fix",
    "is_false_positive": False,
    "fixed_code": "cur.execute('SELECT 1 WHERE id = %s', (uid,))\n",
    "original_code": "cur.execute('SELECT 1 WHERE id = ' + uid)\n",
    "pr_title": "Fix SQL injection in user lookup",
    "pr_description": "Parameterise the query.",
    "file_path": "app/db.py",
}

VALID_TOKEN = "Token test-token"
PR_URL = "https://github.com/acme/payments-api/pull/42"

# Every request the fake API received, as (path, authorization, body).
CALLS: list[tuple[str, str | None, dict]] = []


class FakeOrca(BaseHTTPRequestHandler):
    """The three endpoints the flow uses, plus the failure modes worth testing."""

    def log_message(self, *args):
        pass  # keep test output clean

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        CALLS.append((self.path, self.headers.get("Authorization"), body))

        if self.headers.get("Authorization") != VALID_TOKEN:
            return self._send(403, {"detail": "Insufficient permissions"})

        if self.path == "/api/serving-layer/query":
            alert_id = body["query"]["with"]["values"][0]
            if alert_id == "orca-nocode":
                return self._send(200, {"data": []})  # not a code alert
            if alert_id == "orca-flaky":
                return self._send(502, {"error": "bad gateway"})
            return self._send(
                200,
                {"data": [{"data": {"Inventory": {"data": {"Id": {"value": "ctx-123"}}}}}]},
            )

        if self.path == "/api/ai-core/skills/code_remediation/sast":
            if body["alert_id"] == "orca-fp":
                return self._send(200, {**FIX, "is_false_positive": True})
            if body["alert_id"] == "orca-actionsteps":
                return self._send(200, {**FIX, "remediation_type": "action_steps"})
            return self._send(200, FIX)

        if self.path == "/api/shiftleft/repository_contexts/ctx-123/pull_requests/":
            return self._send(201, {"url": PR_URL})

        self._send(404, {"error": f"unexpected path {self.path}"})

    def _send(self, status: int, payload: dict):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def sample(name: str) -> dict:
    return json.loads((SAMPLES / f"{name}.json").read_text())


def pr_calls() -> list[tuple[str, str | None, dict]]:
    return [c for c in CALLS if c[0].endswith("/pull_requests/")]


def ai_calls() -> list[tuple[str, str | None, dict]]:
    return [c for c in CALLS if "ai-core" in c[0]]


class WebhookIntegration(unittest.TestCase):
    server: HTTPServer
    client: object
    main: object

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeOrca)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{cls.server.server_address[1]}"

        # orca_codefix reads ORCA_API_BASE at import time, so set it first.
        cls._saved_env = dict(os.environ)
        os.environ.update(
            ORCA_API_BASE=base,
            ORCA_API_TOKEN="test-token",
            WEBHOOK_SECRET="s3cret",
            CREATE_PR="true",
            LOG_LEVEL="CRITICAL",
        )
        os.environ.pop("ORCA_AUTH", None)
        os.environ.pop("ALERT_TYPE_ALLOWLIST", None)

        import orca_codefix

        importlib.reload(orca_codefix)
        import main

        cls.main = importlib.reload(main)

        import flask

        app = flask.Flask(__name__)
        # The Functions Framework passes flask.request into the handler; plain
        # Flask calls the view with no arguments, so bridge the two here.
        app.route("/", methods=["GET", "POST", "PUT"])(
            lambda: cls.main.orca_webhook(flask.request)
        )
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        os.environ.clear()
        os.environ.update(cls._saved_env)

    def setUp(self):
        CALLS.clear()
        self.main._seen.clear()
        os.environ["ORCA_API_TOKEN"] = "test-token"
        os.environ.pop("ALERT_TYPE_ALLOWLIST", None)

    def post(self, payload, secret="s3cret", raw=None):
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            headers["X-Orca-Webhook-Token"] = secret
        if raw is not None:
            return self.client.post("/", data=raw, headers=headers)
        return self.client.post("/", json=payload, headers=headers)

    # --- health check ---------------------------------------------------------

    def test_get_is_a_health_check(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["create_pr"])
        self.assertTrue(body["auth_required"])

    def test_other_methods_rejected(self):
        self.assertEqual(self.client.put("/").status_code, 405)

    # --- auth ----------------------------------------------------------------

    def test_missing_secret_is_401(self):
        self.assertEqual(self.post({"alert_id": "orca-1"}, secret=None).status_code, 401)

    def test_wrong_secret_is_401(self):
        self.assertEqual(self.post({"alert_id": "orca-1"}, secret="bad").status_code, 401)

    def test_rejected_request_never_reaches_orca(self):
        self.post({"alert_id": "orca-1"}, secret="bad")
        self.assertEqual(CALLS, [])

    # --- bad input -----------------------------------------------------------

    def test_non_json_body_is_400(self):
        self.assertEqual(self.post(None, raw="not json at all").status_code, 400)

    def test_payload_without_an_alert_id_is_400(self):
        self.assertEqual(self.post({"description": "nothing here"}).status_code, 400)

    # --- the happy path ------------------------------------------------------

    def test_wrapper_payload_opens_a_pull_request(self):
        resp = self.post(sample("wrapper"))
        self.assertEqual(resp.status_code, 200)
        result = resp.get_json()["results"][0]
        self.assertEqual(result["status"], "pr_opened")
        self.assertEqual(result["pull_request_url"], PR_URL)
        self.assertEqual(result["repository_context_id"], "ctx-123")

    def test_legacy_payload_opens_a_pull_request(self):
        resp = self.post(sample("legacy"))
        self.assertEqual(resp.get_json()["results"][0]["status"], "pr_opened")

    def test_pr_body_is_the_documented_remap(self):
        self.post(sample("wrapper"))
        _, _, body = pr_calls()[-1]
        self.assertEqual(body["title"], FIX["pr_title"])
        self.assertEqual(body["description"], FIX["pr_description"])
        self.assertEqual(body["file_path"], FIX["file_path"])
        self.assertEqual(body["alert_id"], "orca-1596292")
        self.assertEqual(body["alert_url"], "https://app.orcasecurity.io/alerts/orca-1596292")
        self.assertEqual(base64.b64decode(body["fixed_content"]).decode(), FIX["fixed_code"])

    def test_patch_is_not_echoed_in_the_response(self):
        # The response goes back to Orca, which discards it; the patch is in the PR.
        result = self.post(sample("wrapper")).get_json()["results"][0]
        self.assertNotIn("fix", result)
        self.assertNotIn("fixed_code", result)

    def test_batch_payload_processes_every_alert(self):
        body = self.post(sample("batch")).get_json()
        self.assertEqual(body["processed"], 2)
        self.assertEqual(len(pr_calls()), 2)

    # --- retries and idempotency ---------------------------------------------

    def test_retry_of_the_same_alert_opens_no_second_pr(self):
        self.post(sample("wrapper"))
        self.assertEqual(len(pr_calls()), 1)
        result = self.post(sample("wrapper")).get_json()["results"][0]
        self.assertTrue(result["deduplicated"])
        self.assertEqual(len(pr_calls()), 1)

    def test_dedupe_window_is_bounded(self):
        self.main._seen.clear()
        for i in range(self.main._DEDUPE_WINDOW + 50):
            self.main._remember(f"orca-{i}", {"status": "pr_opened"})
        self.assertEqual(len(self.main._seen), self.main._DEDUPE_WINDOW)
        # The oldest entries are the ones dropped.
        self.assertNotIn("orca-0", self.main._seen)
        self.assertIn(f"orca-{self.main._DEDUPE_WINDOW + 49}", self.main._seen)

    # --- alerts with nothing to do -------------------------------------------

    def test_false_positive_is_skipped_without_a_pr(self):
        result = self.post({"alert_id": "orca-fp"}).get_json()["results"][0]
        self.assertEqual(result["status"], "skipped_false_positive")
        self.assertEqual(pr_calls(), [])

    def test_action_steps_remediation_is_skipped_without_a_pr(self):
        result = self.post({"alert_id": "orca-actionsteps"}).get_json()["results"][0]
        self.assertEqual(result["status"], "skipped_no_code_fix")
        self.assertEqual(pr_calls(), [])

    def test_alert_with_no_code_repository_errors_without_retrying(self):
        resp = self.post({"alert_id": "orca-nocode"})
        self.assertEqual(resp.status_code, 200)  # permanent: do not ask Orca to retry
        result = resp.get_json()["results"][0]
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["retryable"])

    def test_non_code_alert_spends_no_ai_metering_unit(self):
        # The step 1 lookup gates step 2, which is the billable call.
        self.post({"alert_id": "orca-nocode"})
        self.assertEqual(ai_calls(), [])

    # --- filtering -----------------------------------------------------------

    def test_type_allowlist_ignores_non_matching_alerts(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        body = self.post({"alert_id": "orca-555", "type_key": "unpatched_os"}).get_json()
        self.assertEqual(body["status"], "ignored")
        self.assertEqual(CALLS, [])

    def test_type_allowlist_still_admits_matching_alerts(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        body = self.post(sample("wrapper")).get_json()
        self.assertEqual(body["results"][0]["status"], "pr_opened")

    # --- error propagation ---------------------------------------------------

    def test_orca_403_is_permanent_so_the_function_returns_200(self):
        os.environ["ORCA_API_TOKEN"] = "wrong-token"
        resp = self.post({"alert_id": "orca-777"})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["results"][0]["retryable"])

    def test_orca_5xx_is_retryable_so_the_function_returns_503(self):
        resp = self.post({"alert_id": "orca-flaky"})
        self.assertEqual(resp.status_code, 503)
        self.assertTrue(resp.get_json()["results"][0]["retryable"])

    def test_a_mixed_batch_does_not_ask_for_a_retry(self):
        # One transient failure alongside a success must not replay the success.
        body = self.post(
            {"alerts": [{"alert_id": "orca-1596292"}, {"alert_id": "orca-flaky"}]}
        ).get_json()
        self.assertEqual(len(body["results"]), 2)
        self.assertEqual(body["status"], "processed")

    def test_max_alerts_per_request_is_enforced(self):
        os.environ["MAX_ALERTS_PER_REQUEST"] = "1"
        try:
            body = self.post(sample("batch")).get_json()
            self.assertEqual(body["processed"], 1)
            self.assertEqual(body["not_processed"], ["orca-1596293"])
        finally:
            os.environ.pop("MAX_ALERTS_PER_REQUEST", None)


class Logging(unittest.TestCase):
    """The bug this guards: INFO records were silently dropped in production.

    logging.basicConfig() is a no-op once a host framework has configured root
    logging, which left the module logger with no handler at level WARNING, so
    successful runs logged nothing at all.
    """

    def test_info_survives_a_prior_root_logging_config(self):
        import io
        import json as _json
        import logging as _logging

        # Reproduce the Functions Framework's setup: root configured first.
        root = _logging.getLogger()
        saved = root.handlers[:]
        root.handlers = [_logging.NullHandler()]
        try:
            import main as _main

            logger = _main._configure_logging()
            self.assertTrue(logger.handlers, "logger must own a handler")
            self.assertEqual(logger.level, _logging.INFO)

            buf = io.StringIO()
            logger.handlers[0].stream = buf
            logger.info("hello", extra={"context": {"alert_id": "orca-1"}})
            line = buf.getvalue().strip()
            self.assertTrue(line, "INFO record must be emitted, not dropped")

            entry = _json.loads(line)
            self.assertEqual(entry["severity"], "INFO")
            self.assertEqual(entry["message"], "hello")
            self.assertEqual(entry["alert_id"], "orca-1")
        finally:
            root.handlers = saved

    def test_records_are_not_emitted_twice(self):
        import main as _main

        self.assertFalse(_main.log.propagate)

if __name__ == "__main__":
    unittest.main(verbosity=2)
