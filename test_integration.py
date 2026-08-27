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
            models = body["query"]["models"]

            # Second-stage lookup: cloud asset -> the repo whose IaC deployed it.
            if models == ["CodeOrigin"]:
                asset = body["query"]["with"]["with"]["with"]["values"][0]
                if asset == "asset-no-origin":
                    return self._send(200, {"data": []})
                return self._send(
                    200,
                    {"data": [{"data": {"CodeRepository": {"data": {"Id": {"value": "ctx-iac"}}}}}]},
                )

            alert_id = body["query"]["with"]["values"][0]
            if alert_id == "orca-noasset":
                return self._send(200, {"data": []})
            if alert_id == "orca-flaky":
                return self._send(502, {"error": "bad gateway"})

            # A cloud resource, i.e. a CSPM alert: no Id field, so the repo can
            # only come from its code origin.
            if alert_id in ("orca-cspm", "orca-nocode"):
                asset = "asset-no-origin" if alert_id == "orca-nocode" else "asset-1"
                return self._send(
                    200,
                    {"data": [{"data": {"Inventory": {
                        "id": asset, "type": "AwsS3Bucket", "data": {"Name": {"value": "b"}}}}}]},
                )

            return self._send(
                200,
                {"data": [{"data": {"Inventory": {
                    "id": "asset-repo", "type": "CodeRepository",
                    "data": {"Id": {"value": "ctx-123"}}}}}]},
            )

        if self.path == "/api/ai-core/skills/code_remediation/c2d":
            return self._send(200, {**FIX, "file_path": "terraform/s3.tf"})

        if self.path == "/api/ai-core/skills/code_remediation/sast":
            if body["alert_id"] == "orca-fp":
                return self._send(200, {**FIX, "is_false_positive": True})
            if body["alert_id"] == "orca-actionsteps":
                return self._send(200, {**FIX, "remediation_type": "action_steps"})
            return self._send(200, FIX)

        if self.path.startswith("/api/shiftleft/repository_contexts/") and self.path.endswith(
            "/pull_requests/"
        ):
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

    def test_alert_with_no_code_repository_is_skipped_without_retrying(self):
        # Not an error: most CSPM alerts describe resources never deployed from
        # IaC Orca can see, so this is the expected outcome, not a fault.
        resp = self.post({"alert_id": "orca-nocode"})
        self.assertEqual(resp.status_code, 200)  # permanent: do not ask Orca to retry
        self.assertEqual(resp.get_json()["results"][0]["status"], "skipped_no_code_origin")

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


class CodeToCloud(WebhookIntegration):
    """CSPM alerts: the repo comes from code origin, and the skill is c2d.

    The alert's asset type is what selects the route — not its category, of which
    CSPM alone has hundreds.
    """

    def test_cspm_alert_resolves_via_code_origin_and_uses_c2d(self):
        result = self.post({"alert_id": "orca-cspm"}).get_json()["results"][0]
        self.assertEqual(result["status"], "pr_opened")
        self.assertEqual(result["repository_context_id"], "ctx-iac")
        self.assertEqual(result["skill"], "c2d")
        self.assertEqual(result["file_path"], "terraform/s3.tf")

    def test_cspm_alert_calls_the_c2d_endpoint_not_sast(self):
        self.post({"alert_id": "orca-cspm"})
        paths = [c[0] for c in CALLS if "ai-core" in c[0]]
        self.assertEqual(paths, ["/api/ai-core/skills/code_remediation/c2d"])

    def test_sast_alert_still_uses_the_sast_endpoint(self):
        self.post(sample("wrapper"))
        paths = [c[0] for c in CALLS if "ai-core" in c[0]]
        self.assertEqual(paths, ["/api/ai-core/skills/code_remediation/sast"])
        self.assertEqual(CALLS[-1][0], "/api/shiftleft/repository_contexts/ctx-123/pull_requests/")

    def test_pr_opens_against_the_iac_repo_for_cspm(self):
        self.post({"alert_id": "orca-cspm"})
        self.assertEqual(
            pr_calls()[-1][0], "/api/shiftleft/repository_contexts/ctx-iac/pull_requests/"
        )

    def test_asset_without_code_origin_is_skipped_not_errored(self):
        # The common CSPM case: nothing was deployed from IaC Orca can see.
        resp = self.post({"alert_id": "orca-nocode"})
        self.assertEqual(resp.status_code, 200)
        result = resp.get_json()["results"][0]
        self.assertEqual(result["status"], "skipped_no_code_origin")

    def test_skip_costs_no_ai_metering_unit(self):
        self.post({"alert_id": "orca-nocode"})
        self.assertEqual(ai_calls(), [])

    def test_alert_with_no_asset_at_all_is_skipped(self):
        result = self.post({"alert_id": "orca-noasset"}).get_json()["results"][0]
        self.assertEqual(result["status"], "skipped_no_code_origin")

    def test_skips_are_not_cached_so_a_later_scan_can_succeed(self):
        # A code origin can appear after the next IaC scan; caching the skip would
        # mean never retrying. Nothing was spent, so replaying is cheap.
        self.post({"alert_id": "orca-nocode"})
        self.assertNotIn("orca-nocode", self.main._seen)


class UrlSafety(unittest.TestCase):
    """The URL is built from an env var and an API-response value, so both are
    constrained: urllib honours file:// and a path segment must not escape."""

    def setUp(self):
        self._saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def _reload(self):
        import orca_codefix

        return importlib.reload(orca_codefix)

    def test_https_is_accepted(self):
        os.environ["ORCA_API_BASE"] = "https://api.orcasecurity.io"
        oc = self._reload()
        self.assertEqual(
            oc.resolve_url("/api/x"), "https://api.orcasecurity.io/api/x"
        )

    def test_file_scheme_is_refused(self):
        os.environ["ORCA_API_BASE"] = "file:///etc"
        oc = self._reload()
        with self.assertRaises(oc.OrcaError) as ctx:
            oc.resolve_url("/passwd")
        self.assertIn("non-HTTPS", str(ctx.exception))

    def test_other_schemes_are_refused(self):
        for base in ("ftp://host", "gopher://host", "http://evil.example.com"):
            os.environ["ORCA_API_BASE"] = base
            oc = self._reload()
            with self.assertRaises(oc.OrcaError):
                oc.resolve_url("/api/x")

    def test_plain_http_allowed_only_on_loopback(self):
        # The test suite points at a local stand-in, so this must keep working.
        os.environ["ORCA_API_BASE"] = "http://127.0.0.1:8123"
        oc = self._reload()
        self.assertEqual(oc.resolve_url("/api/x"), "http://127.0.0.1:8123/api/x")

    def test_trailing_slash_on_base_does_not_double_up(self):
        os.environ["ORCA_API_BASE"] = "https://api.orcasecurity.io/"
        oc = self._reload()
        self.assertEqual(oc.resolve_url("/api/x"), "https://api.orcasecurity.io/api/x")

    def test_repo_context_id_cannot_escape_its_path_segment(self):
        oc = self._reload()
        for bad in ("../../etc/passwd", "a/b", "a.b", "a:b", "a%2f", "", "x" * 200):
            with self.assertRaises(oc.OrcaError, msg=bad):
                oc.open_pull_request("orca-1", bad, {}, auth="Token t")

    def test_repo_context_id_accepts_a_real_uuid(self):
        oc = self._reload()
        self.assertTrue(oc.PATH_SEGMENT_RE.match("019cd7cc-3a1f-753a-9aad-a19d9141f8b4"))


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
