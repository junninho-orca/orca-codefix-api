#!/usr/bin/env python3
"""Tests for the webhook parsing and auth layer. Standard library only:

    python3 test_webhook.py

These cover the parts that see untrusted input. The Orca API calls themselves are
covered by running the CLI against a real alert.
"""

from __future__ import annotations

import json
import os
import pathlib
import unittest

import webhook

SAMPLES = pathlib.Path(__file__).with_name("samples")


def sample(name: str) -> dict:
    return json.loads((SAMPLES / f"{name}.json").read_text())


class EnvTestCase(unittest.TestCase):
    """Base class that restores os.environ after each test."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        for key in (
            "WEBHOOK_SECRET",
            "WEBHOOK_SECRET_HEADER",
            "ALLOW_UNAUTHENTICATED",
            "ALERT_TYPE_ALLOWLIST",
        ):
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)


class ExtractAlertIds(EnvTestCase):
    def test_wrapper_format(self):
        self.assertEqual(webhook.extract_alert_ids(sample("wrapper")), ["orca-1596292"])

    def test_legacy_format(self):
        self.assertEqual(webhook.extract_alert_ids(sample("legacy")), ["orca-1596292"])

    def test_minimal_body_template(self):
        self.assertEqual(webhook.extract_alert_ids(sample("minimal")), ["orca-1596292"])

    def test_serving_layer_value_wrapped_fields(self):
        # Orca's newer payloads wrap every field: "AlertId": {"value": "orca-1"}.
        self.assertEqual(webhook.extract_alert_ids(sample("serving_layer")), ["orca-1590385"])

    def test_value_wrapped_id_at_a_nested_path(self):
        payload = {"state": {"alert_id": {"value": "orca-42"}}}
        self.assertEqual(webhook.extract_alert_ids(payload), ["orca-42"])

    def test_value_wrapper_holding_a_non_id_is_rejected(self):
        with self.assertRaises(webhook.WebhookError):
            webhook.extract_alert_ids({"alert_id": {"value": "not-an-alert"}})

    def test_batch_under_data(self):
        self.assertEqual(
            webhook.extract_alert_ids(sample("batch")), ["orca-1596292", "orca-1596293"]
        )

    def test_bare_list(self):
        payload = [{"alert_id": "orca-1"}, {"state": {"alert_id": "orca-2"}}]
        self.assertEqual(webhook.extract_alert_ids(payload), ["orca-1", "orca-2"])

    def test_duplicates_collapse(self):
        payload = {"alerts": [{"alert_id": "orca-1"}, {"alert_id": "orca-1"}]}
        self.assertEqual(webhook.extract_alert_ids(payload), ["orca-1"])

    def test_alerts_key_batch(self):
        payload = {"alerts": [{"alert_id": "orca-7"}]}
        self.assertEqual(webhook.extract_alert_ids(payload), ["orca-7"])

    def test_missing_id_is_rejected(self):
        with self.assertRaises(webhook.WebhookError) as ctx:
            webhook.extract_alert_ids({"description": "no id here"})
        self.assertEqual(ctx.exception.status, 400)

    def test_malformed_id_is_rejected(self):
        # A value that isn't an Orca alert id must never reach an API call.
        for bad in ("../../etc/passwd", "orca-1; DROP TABLE", "", "12345", None, 42):
            with self.assertRaises(webhook.WebhookError):
                webhook.extract_alert_ids({"alert_id": bad})

    def test_wrapper_is_not_unwrapped_when_data_is_a_list(self):
        # extract_alerts must fan out rather than treat the list as one alert.
        self.assertEqual(len(webhook.extract_alerts(sample("batch"))), 2)


class TypeFilter(EnvTestCase):
    def test_no_allowlist_accepts_everything(self):
        self.assertEqual(webhook.extract_alert_ids({"alert_id": "orca-1"}), ["orca-1"])

    def test_allowlist_matches_case_insensitively(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        self.assertEqual(webhook.extract_alert_ids(sample("wrapper")), ["orca-1596292"])

    def test_allowlist_matches_nested_state(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "code security"
        self.assertEqual(webhook.extract_alert_ids(sample("legacy")), ["orca-1596292"])

    def test_allowlist_matches_value_wrapped_fields(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        self.assertEqual(webhook.extract_alert_ids(sample("serving_layer")), ["orca-1590385"])

    def test_allowlist_filters_value_wrapped_non_matching_out(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        payload = {"AlertId": {"value": "orca-9"}, "AppsecScanType": {"value": "IaC"}}
        self.assertEqual(webhook.extract_alert_ids(payload), [])

    def test_allowlist_filters_non_matching_out(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        payload = {"alert_id": "orca-1", "type_key": "unpatched_os"}
        self.assertEqual(webhook.extract_alert_ids(payload), [])

    def test_allowlist_keeps_only_matching_alerts_in_a_batch(self):
        os.environ["ALERT_TYPE_ALLOWLIST"] = "sast"
        payload = {
            "alerts": [
                {"alert_id": "orca-1", "type_key": "sast_finding"},
                {"alert_id": "orca-2", "type_key": "unpatched_os"},
            ]
        }
        self.assertEqual(webhook.extract_alert_ids(payload), ["orca-1"])


class VerifySecret(EnvTestCase):
    def test_missing_config_fails_closed_with_500(self):
        with self.assertRaises(webhook.WebhookError) as ctx:
            webhook.verify_secret({})
        self.assertEqual(ctx.exception.status, 500)

    def test_correct_custom_header_passes(self):
        os.environ["WEBHOOK_SECRET"] = "s3cret"
        webhook.verify_secret({"X-Orca-Webhook-Token": "s3cret"})

    def test_wrong_secret_is_401(self):
        os.environ["WEBHOOK_SECRET"] = "s3cret"
        with self.assertRaises(webhook.WebhookError) as ctx:
            webhook.verify_secret({"X-Orca-Webhook-Token": "nope"})
        self.assertEqual(ctx.exception.status, 401)

    def test_absent_header_is_401(self):
        os.environ["WEBHOOK_SECRET"] = "s3cret"
        with self.assertRaises(webhook.WebhookError) as ctx:
            webhook.verify_secret({})
        self.assertEqual(ctx.exception.status, 401)

    def test_authorization_bearer_and_token_prefixes(self):
        os.environ["WEBHOOK_SECRET"] = "s3cret"
        for value in ("Bearer s3cret", "Token s3cret", "s3cret"):
            webhook.verify_secret({"Authorization": value})

    def test_custom_header_name(self):
        os.environ["WEBHOOK_SECRET"] = "s3cret"
        os.environ["WEBHOOK_SECRET_HEADER"] = "X-Custom-Auth"
        webhook.verify_secret({"X-Custom-Auth": "s3cret"})

    def test_allow_unauthenticated_bypasses_the_check(self):
        os.environ["ALLOW_UNAUTHENTICATED"] = "true"
        webhook.verify_secret({})


class EnvFlag(EnvTestCase):
    def test_truthy_and_falsey_spellings(self):
        for value in ("1", "true", "TRUE", "yes", "on", " true "):
            os.environ["X"] = value
            self.assertTrue(webhook.env_flag("X"), value)
        for value in ("0", "false", "no", "off", "", "  "):
            os.environ["X"] = value
            self.assertFalse(webhook.env_flag("X"), value)

    def test_unset_uses_the_default(self):
        os.environ.pop("X", None)
        self.assertFalse(webhook.env_flag("X"))
        self.assertTrue(webhook.env_flag("X", default=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
