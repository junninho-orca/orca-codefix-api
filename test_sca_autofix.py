#!/usr/bin/env python3
"""Tests for the SCA alert listing and filtering helpers. Standard library only:

    python3 test_sca_autofix.py

These cover the part that decides which alerts a scheduled run acts on. Nothing
here touches Orca, GitHub or Claude; the side-effecting functions in
sca_autofix.py are exercised by the workflow's dry-run dispatch.
"""

from __future__ import annotations

import datetime as dt
import unittest

import sca_autofix

NOW = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)


def record(
    alert_id: str,
    *,
    hours_ago: float | None = 1,
    status: str = "open",
    category: str = "Vulnerabilities",
    inventory_type: str | None = "CodeRepository",
    asset_type: str | None = None,
    labels: list | None = None,
    created_key: str = "CreatedAt",
    created_value: object = None,
) -> dict:
    """A serving-layer alert record with every field {"value": ...} wrapped."""
    data = {
        "AlertId": {"value": alert_id},
        "Status": {"value": status},
        "Category": {"value": category},
    }
    if hours_ago is not None or created_value is not None:
        if created_value is None:
            created_value = (NOW - dt.timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")
        data[created_key] = {"value": created_value}
    if asset_type is not None:
        data["AssetData"] = {"value": {"asset_name": "org/repo", "asset_type": asset_type}}
    if labels is not None:
        data["Labels"] = {"value": labels}
    if inventory_type is not None:
        data["Inventory"] = {"id": "uuid-1", "type": inventory_type, "data": {}}
    return {"data": data}


class BuildQuery(unittest.TestCase):
    def test_scheduled_query_bounds_on_status_and_category(self):
        body = sca_autofix.build_query()
        self.assertEqual(body["query"]["models"], ["Alert"])
        keys = {clause["key"]: clause["values"] for clause in body["query"]["with"]["values"]}
        self.assertEqual(keys, {"Status": ["open"], "Category": ["Vulnerabilities"]})
        self.assertIn("Inventory", body["additional_models[]"])

    def test_scheduled_query_adds_a_created_at_lower_bound(self):
        since = dt.datetime(2026, 9, 3, 10, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))
        body = sca_autofix.build_query(since=since)
        clause = [c for c in body["query"]["with"]["values"] if c["key"] == "CreatedAt"][0]
        self.assertEqual(clause["values"], ["2026-09-03T08:00:00+00:00"])
        self.assertEqual((clause["type"], clause["operator"]), ("datetime", "gte"))

    def test_on_demand_query_is_the_by_id_lookup(self):
        body = sca_autofix.build_query("orca-42", since=NOW)
        self.assertEqual(
            body["query"]["with"],
            {"key": "AlertId", "values": ["orca-42"], "type": "str", "operator": "eq"},
        )

    def test_malformed_id_never_reaches_the_query(self):
        for bad in ("../../x", "orca-1; DROP TABLE", "", "12345"):
            with self.assertRaises(ValueError):
                sca_autofix.build_query(bad)


class CreatedAt(unittest.TestCase):
    def test_iso_with_z(self):
        rec = record("orca-1", created_value="2026-09-04T10:30:00Z")
        self.assertEqual(
            sca_autofix.created_at(rec), dt.datetime(2026, 9, 4, 10, 30, tzinfo=dt.timezone.utc)
        )

    def test_iso_with_offset_is_normalised_to_utc(self):
        rec = record("orca-1", created_value="2026-09-04T12:30:00+02:00")
        self.assertEqual(
            sca_autofix.created_at(rec), dt.datetime(2026, 9, 4, 10, 30, tzinfo=dt.timezone.utc)
        )

    def test_epoch_seconds_and_milliseconds(self):
        want = dt.datetime(2026, 9, 4, 10, 30, tzinfo=dt.timezone.utc)
        secs = int(want.timestamp())
        self.assertEqual(sca_autofix.created_at(record("orca-1", created_value=secs)), want)
        self.assertEqual(sca_autofix.created_at(record("orca-1", created_value=secs * 1000)), want)

    def test_alternate_field_names(self):
        for key in ("CreationTime", "FirstSeen", "created_at"):
            rec = record("orca-1", created_key=key, created_value="2026-09-04T10:30:00Z")
            self.assertIsNotNone(sca_autofix.created_at(rec), key)

    def test_missing_or_garbage_is_none(self):
        self.assertIsNone(sca_autofix.created_at(record("orca-1", hours_ago=None)))
        self.assertIsNone(sca_autofix.created_at(record("orca-1", created_value="yesterday")))
        self.assertIsNone(sca_autofix.created_at(record("orca-1", created_value=True)))


class IsScaAlert(unittest.TestCase):
    def test_code_repository_inventory(self):
        self.assertTrue(sca_autofix.is_sca_alert(record("orca-1")))

    def test_asset_data_type_without_inventory(self):
        rec = record("orca-1", inventory_type=None, asset_type="CodeRepository")
        self.assertTrue(sca_autofix.is_sca_alert(rec))

    def test_shiftleft_label_without_inventory(self):
        rec = record("orca-1", inventory_type=None, labels=["source:shiftleft", "fix_available"])
        self.assertTrue(sca_autofix.is_sca_alert(rec))

    def test_runtime_asset_is_not_sca(self):
        rec = record("orca-1", inventory_type="CloudRun", asset_type="CloudRun")
        self.assertFalse(sca_autofix.is_sca_alert(rec))

    def test_non_open_status_is_out(self):
        for status in ("closed", "dismissed", "in_progress", "snoozed"):
            self.assertFalse(sca_autofix.is_sca_alert(record("orca-1", status=status)), status)

    def test_non_vulnerability_category_is_out(self):
        # SAST and IaC findings on the same repository belong to the webhook path.
        for category in ("Data protection", "Best practices", "IAM misconfigurations"):
            self.assertFalse(sca_autofix.is_sca_alert(record("orca-1", category=category)), category)

    def test_unwrapped_legacy_record(self):
        rec = {"AlertId": "orca-1", "Status": "open", "Category": "Vulnerabilities",
               "AssetData": {"asset_type": "CodeRepository"}}
        self.assertTrue(sca_autofix.is_sca_alert(rec))


class SelectAlerts(unittest.TestCase):
    def test_keeps_recent_sca_alerts_newest_first(self):
        records = [
            record("orca-1", hours_ago=20),
            record("orca-2", hours_ago=2),
            record("orca-3", hours_ago=10),
        ]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), ["orca-2", "orca-3", "orca-1"])

    def test_drops_alerts_older_than_the_window(self):
        records = [record("orca-old", hours_ago=27), record("orca-new", hours_ago=25)]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), ["orca-new"])

    def test_window_is_configurable(self):
        records = [record("orca-1", hours_ago=3)]
        self.assertEqual(sca_autofix.select_alerts(records, NOW, lookback_hours=2), [])
        self.assertEqual(sca_autofix.select_alerts(records, NOW, lookback_hours=4), ["orca-1"])

    def test_unreadable_creation_time_is_kept(self):
        # A renamed field must not turn every run into a silent no-op.
        records = [record("orca-1", hours_ago=None)]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), ["orca-1"])

    def test_non_sca_and_closed_alerts_are_dropped(self):
        records = [
            record("orca-1"),
            record("orca-2", inventory_type="CloudRun"),
            record("orca-3", status="closed"),
            record("orca-4", category="Data protection"),
        ]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), ["orca-1"])

    def test_caps_at_the_limit(self):
        records = [record(f"orca-{i}", hours_ago=i) for i in range(1, 9)]
        self.assertEqual(len(sca_autofix.select_alerts(records, NOW)), sca_autofix.MAX_ALERTS)
        self.assertEqual(sca_autofix.select_alerts(records, NOW, limit=2), ["orca-1", "orca-2"])

    def test_duplicates_collapse(self):
        records = [record("orca-1"), record("orca-1")]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), ["orca-1"])

    def test_records_without_an_id_or_of_the_wrong_shape_are_ignored(self):
        records = [{"data": {"Status": {"value": "open"}}}, "junk", None, 42]
        self.assertEqual(sca_autofix.select_alerts(records, NOW), [])

    def test_on_demand_ignores_the_window_but_not_the_sca_check(self):
        records = [record("orca-1", hours_ago=400)]
        self.assertEqual(sca_autofix.select_alerts(records, NOW, alert_id="orca-1"), ["orca-1"])
        records = [record("orca-1", hours_ago=400, inventory_type="CloudRun")]
        self.assertEqual(sca_autofix.select_alerts(records, NOW, alert_id="orca-1"), [])

    def test_on_demand_returns_only_the_requested_id(self):
        records = [record("orca-1"), record("orca-2")]
        self.assertEqual(sca_autofix.select_alerts(records, NOW, alert_id="orca-2"), ["orca-2"])

    def test_on_demand_rejects_a_malformed_id(self):
        with self.assertRaises(ValueError):
            sca_autofix.select_alerts([], NOW, alert_id="orca-1; rm -rf")


class Reporting(unittest.TestCase):
    def test_branch_name(self):
        self.assertEqual(sca_autofix.branch_for("orca-42"), "orca-patch/orca-42")

    def test_prompt_names_the_skill_the_alert_and_the_branch(self):
        prompt = sca_autofix.build_prompt("orca-42", "/tmp/ws")
        self.assertTrue(prompt.startswith("Use the orca-patch skill to patch orca-42 and open the PR"))
        self.assertIn("orca-patch/orca-42", prompt)
        self.assertIn("/tmp/ws", prompt)

    def test_outcome_row_escapes_table_breaking_characters(self):
        row = sca_autofix.outcome_row("orca-1", "no_pr", "a | b\nc")
        self.assertEqual(row, "| orca-1 | no_pr | a / b c |")

    def test_extract_report_finds_the_skill_block(self):
        text = "chatter\n\n## orca-9: lodash prototype pollution\nAsset: x\nPR: not opened"
        report = sca_autofix.extract_report(text, "orca-9")
        self.assertTrue(report.startswith("## orca-9:"))
        self.assertIn("PR: not opened", report)

    def test_extract_report_falls_back_to_the_tail_and_truncates(self):
        text = "x" * 2000
        report = sca_autofix.extract_report(text, "orca-9", limit=100)
        self.assertEqual(len(report), 100)
        self.assertTrue(report.startswith("..."))


if __name__ == "__main__":
    unittest.main(verbosity=2)
