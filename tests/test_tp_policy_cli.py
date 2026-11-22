"""Opt-in TP CLI assembly with temporary source/DB and no external calls."""
import json
import unittest
from unittest.mock import patch

import test_tp_policy as fixtures
from fpm_benchmark.codeql import database_fingerprint
from fpm_benchmark.revision_cli import main
from fpm_benchmark.revision_runner import triage_record as real_triage


class SemanticTPCliTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.SemanticTPTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.database = self.root / "database"
        self.database.mkdir()
        (self.database / "codeql-database.yml").write_text("primaryLanguage: java\n")
        self.database_hash = database_fingerprint(self.database)
        self.case.record["analysis_provenance"]["database_hash"] = self.database_hash
        self.inputs = self.root / "input.jsonl"
        self.inputs.write_text(json.dumps(self.case.record) + "\n")
        self.config_path = self.root / "config.json"
        self.config = {"manifest": str(self.case.manifest_file), "database": str(self.database),
            "llm": {"base_url": "https://example.test", "model": "test", "api_key_env": "UNUSED"},
            "tp_policy": self.case.config()}
        self.config_path.write_text(json.dumps(self.config))
        self.output = self.root / "results/out.jsonl"
        self.command = ["run", "--config", str(self.config_path), "--input", str(self.inputs),
            "--out", str(self.output), "--method", "queryfpm", "--budget", "0"]

    def row(self):
        return json.loads(self.output.read_text().strip())

    def test_optional_tp_is_explicitly_unverified_and_frozen(self):
        client = fixtures.Client([fixtures.proposal()])
        with patch("fpm_benchmark.revision_cli.make_client", return_value=client):
            self.assertEqual(main(self.command), 0)
        row = self.row()
        self.assertEqual(row["decision"]["verdict"], "TP")
        self.assertEqual(row["decision"]["verification"], "model_classified_unverified")
        self.assertEqual(row["operation"], "KEEP")
        self.assertEqual(client.calls, 1)
        saved = json.loads(self.output.with_suffix(".manifest.json").read_text())
        self.assertEqual(saved["frozen"]["tp_policy"], row["tp_policy"])
        self.assertEqual(row["authorization"]["query_budget"], 0)

    def test_tp_option_does_not_enable_source_fp_permission(self):
        with patch("fpm_benchmark.revision_cli.make_client", return_value=fixtures.Client([fixtures.proposal("FP")])):
            self.assertEqual(main(self.command), 0)
        self.assertEqual(self.row()["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(self.row()["operation"], "KEEP")
        self.assertNotIn("fp_policy", self.row())

    def test_both_options_keep_tp_conflict_authority_strict(self):
        self.config["fp_policy"] = {"mode": "source_location_unverified",
            "source_root": str(self.case.source), "source_manifest": str(self.case.source_manifest)}
        self.config_path.write_text(json.dumps(self.config))
        with patch("fpm_benchmark.revision_cli.make_client", return_value=fixtures.Client([fixtures.proposal()])):
            self.assertEqual(main(self.command), 0)
        row = self.row()
        self.assertEqual(row["decision"]["verdict"], "TP")
        self.assertFalse(row["authorization"]["original_fp_gate"]["authorized"])
        self.assertEqual(row["operation"], "KEEP")

    def test_default_semantic_tp_behavior_is_unchanged(self):
        self.config.pop("tp_policy")
        self.config_path.write_text(json.dumps(self.config))
        with patch("fpm_benchmark.revision_cli.make_client", return_value=fixtures.Client([fixtures.proposal()])):
            self.assertEqual(main(self.command), 0)
        self.assertEqual(self.row()["decision"]["verdict"], "UNKNOWN")

    def test_no_database_or_wrong_database_fails_before_client(self):
        self.config["database"] = None
        self.config_path.write_text(json.dumps(self.config))
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "optional TP policy requires"):
                main(self.command)
            client.assert_not_called()
        self.config["database"] = str(self.database)
        self.config_path.write_text(json.dumps(self.config))
        (self.database / "codeql-database.yml").write_text("primaryLanguage: java\nname: changed\n")
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "selected database snapshot"):
                main(self.command)
            client.assert_not_called()

    def test_threshold_change_cannot_resume_old_run(self):
        with patch("fpm_benchmark.revision_cli.make_client", return_value=fixtures.Client([fixtures.proposal()])):
            self.assertEqual(main(self.command), 0)
        self.config["tp_policy"]["minimum_successful_queries_before_tp"] = 1
        self.config_path.write_text(json.dumps(self.config))
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                main(self.command + ["--resume"])
            client.assert_not_called()

    def test_two_query_cli_run_uses_controller_owned_fake_executor(self):
        command = self.command.copy()
        command[-1] = "2"
        client = fixtures.Client([fixtures.proposal()])
        execute, calls = self.case.executor()
        def injected_executor(evidence, request):
            result = execute(evidence, request)
            result["provenance"]["database_hash"] = self.database_hash
            return result
        def triage(*args, **kwargs):
            return real_triage(*args, **kwargs, query_executor=injected_executor)
        with patch("fpm_benchmark.revision_cli.make_client", return_value=client), \
             patch("fpm_benchmark.revision_cli.triage_record", side_effect=triage):
            self.assertEqual(main(command), 0)
        self.assertEqual((client.calls, len(calls)), (3, 2))
        self.assertEqual(self.row()["decision"]["verdict"], "TP")


if __name__ == "__main__":
    unittest.main()
