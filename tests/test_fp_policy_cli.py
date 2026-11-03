"""Actual revised CLI with an in-memory client; no model or CodeQL invocation."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from fpm_benchmark.revision_cli import main
from fpm_benchmark.codeql import database_fingerprint
from fpm_benchmark import codeql
from fpm_benchmark.fp_policy import build_fp_policy


class SourcePolicyCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fpm-source-cli-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.file = self.source / "Case.java"
        self.file.write_text("class Case { void sink(String value) { writer.print(value); } }\n")
        self.source_manifest = self.root / "source_hashes.json"
        self.update_source_manifest()
        self.manifest = self.root / "templates.json"
        self.manifest.write_text('{"templates": []}')
        self.database = self.root / "database"
        self.database.mkdir()
        (self.database / "codeql-database.yml").write_text("primaryLanguage: java\n")
        self.database_hash = database_fingerprint(self.database)
        self.config = self.root / "config.json"
        self.settings = {"manifest": str(self.manifest), "database": str(self.database), "workers": 2,
            "llm": {"base_url": "https://example.test", "model": "test", "api_key_env": "UNUSED"},
            "fp_policy": {"mode": "source_location_unverified", "source_root": str(self.source),
                          "source_manifest": str(self.source_manifest)}}
        self.config.write_text(json.dumps(self.settings))
        self.inputs = self.root / "input.jsonl"
        self.rows = [{"alert_id": "opaque-" + str(i), "analysis_provenance": {"language": "java",
            "database_hash": self.database_hash, "sarif_sha256": "b" * 64},
            "alert_contract": {"cwe": "CWE-079", "primary_location": {
                "file": "Case.java", "start_line": 1, "start_column": 1}}, "annotated_trace": [],
            "ground_truth": {"alert_expected_vulnerable": bool(i), "alert_label": "TP" if i else "FP"}}
            for i in range(2)]
        self.inputs.write_text("\n".join(json.dumps(row) for row in self.rows) + "\n")
        self.output = self.root / "out.jsonl"
        self.calls = []
        calls = self.calls
        class Client:
            def chat_json(self, messages, **kwargs):
                calls.append(messages)
                return {"verdict": "FP", "sufficient": True, "missing_evidence": [],
                        "next_query": None, "reason_summary": "synthetic candidate"}, {}
        self.client = Client()
        self.command = ["run", "--config", str(self.config), "--input", str(self.inputs),
                        "--out", str(self.output), "--method", "queryfpm", "--budget", "0"]

    def update_source_manifest(self):
        self.source_manifest.write_text(json.dumps({"files": {
            "Case.java": hashlib.sha256(self.file.read_bytes()).hexdigest()}}))

    def test_cli_freezes_policy_and_resumes_without_new_judgments(self):
        with patch("fpm_benchmark.revision_cli.make_client", return_value=self.client):
            self.assertEqual(main(self.command), 0)
            self.assertEqual(main(self.command + ["--resume"]), 0)
        self.assertEqual(len(self.calls), 2)
        rows = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["operation"] == "SUPPRESS" and not row["decision"]["safety_proven"] for row in rows))
        saved = json.loads(self.output.with_suffix(".manifest.json").read_text())
        self.assertEqual(saved["frozen"]["fp_policy"]["binding_context"]["trusted_alert_count"], 2)
        self.assertEqual(rows[0]["fp_policy"], saved["frozen"]["fp_policy"])
        self.assertNotIn("ground_truth", json.dumps(saved["frozen"]["fp_policy"]))

    def test_source_or_policy_fingerprint_change_rejects_resume_before_client(self):
        with patch("fpm_benchmark.revision_cli.make_client", return_value=self.client):
            self.assertEqual(main(self.command), 0)
        self.file.write_text(self.file.read_text() + "// source revision\n")
        self.update_source_manifest()
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                main(self.command + ["--resume"])
            client.assert_not_called()

    def test_missing_source_and_unsupported_method_fail_before_client(self):
        self.file.unlink()
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "source preflight"):
                main(self.command)
            client.assert_not_called()
        command = self.command.copy()
        command[command.index("queryfpm")] = "matched_one_shot"
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "method=queryfpm"):
                main(command)
            client.assert_not_called()

    def test_missing_policy_config_keeps_the_legacy_gate(self):
        self.settings.pop("fp_policy")
        self.config.write_text(json.dumps(self.settings))
        with patch("fpm_benchmark.revision_cli.make_client", return_value=self.client):
            self.assertEqual(main(self.command), 0)
        rows = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertTrue(all(row["operation"] == "KEEP" and row["decision"]["verdict"] == "UNKNOWN" for row in rows))
        saved = json.loads(self.output.with_suffix(".manifest.json").read_text())
        self.assertNotIn("fp_policy", saved["frozen"])

    def test_zero_budget_mode_requires_database_before_client(self):
        self.settings["database"] = None
        self.config.write_text(json.dumps(self.settings))
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "requires an actual CodeQL database"):
                main(self.command)
            client.assert_not_called()

    def test_actual_database_mismatch_rejected_before_client(self):
        (self.database / "codeql-database.yml").write_text("primaryLanguage: java\nname: changed\n")
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "selected database snapshot"):
                main(self.command)
            client.assert_not_called()

    def test_missing_database_cannot_use_empty_directory_fingerprint(self):
        self.settings["database"] = str(self.root / "does-not-exist")
        self.config.write_text(json.dumps(self.settings))
        for row in self.rows:
            row["analysis_provenance"]["database_hash"] = database_fingerprint(self.settings["database"])
        self.inputs.write_text("\n".join(json.dumps(row) for row in self.rows) + "\n")
        with patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "requires an actual CodeQL database"):
                main(self.command)
            client.assert_not_called()

    def test_context_is_bound_to_the_final_actual_database_fingerprint(self):
        with patch("fpm_benchmark.revision_cli.database_fingerprint",
                   side_effect=[self.database_hash, "f" * 64]), \
             patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "Actual database fingerprint"):
                main(self.command)
            client.assert_not_called()

    def test_positive_query_budget_requires_compatible_executor_before_client(self):
        command = self.command.copy()
        command[command.index("--budget") + 1] = "1"
        for cache in (None, "", "relative-cache", 42):
            with self.subTest(cache=cache):
                self.settings["query_cache_dir"] = cache
                self.config.write_text(json.dumps(self.settings))
                with patch("fpm_benchmark.revision_cli.make_client") as client, \
                     patch("fpm_benchmark.revision_cli._prepare_token_guard") as guard:
                    with self.assertRaisesRegex(ValueError, "absolute query_cache_dir"):
                        main(command)
                    client.assert_not_called()
                    guard.assert_not_called()
                self.assertFalse(self.output.with_suffix(".records").exists())
                self.assertFalse(self.output.with_suffix(".manifest.json").exists())

    def prepare_actual_template(self):
        self.manifest = Path(__file__).resolve().parents[1] / "templates/codeql/templates.json"
        self.settings.update({"manifest": str(self.manifest), "workers": 1,
                              "codeql_bin": "never-executed-codeql"})
        self.config.write_text(json.dumps(self.settings))
        return json.loads(self.manifest.read_text())

    @staticmethod
    def synthetic_codeql_io(command, **kwargs):
        # Keep both real executor/render/provenance paths intact; only replace
        # the external process boundary with a successful empty BQRS fixture.
        if command[1:3] == ["bqrs", "decode"]:
            target = Path(command[command.index("--output") + 1])
            target.write_text(json.dumps({"#select": {"columns": [{"kind": "String"}] * 11,
                                                      "tuples": []}}))
        elif command[1:3] != ["query", "run"]:
            raise AssertionError("Unexpected subprocess boundary")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def test_actual_cli_batch_backend_provenance_reaches_optional_fp_gate(self):
        self.prepare_actual_template()
        self.settings["query_cache_dir"] = str(self.root / "isolated-cache")
        self.config.write_text(json.dumps(self.settings))
        command = self.command.copy()
        command[command.index("--budget") + 1] = "1"
        calls = {}
        class Client:
            def chat_json(self, messages, **kwargs):
                alert_id = json.loads(messages[1]["content"])["evidence"]["alert_id"]
                calls[alert_id] = calls.get(alert_id, 0) + 1
                if calls[alert_id] == 1:
                    return {"verdict": "UNKNOWN", "sufficient": False,
                            "missing_evidence": ["synthetic query wiring"],
                            "next_query": {"template_id": "find-bound-fixed-sink", "parameters": {}},
                            "reason_summary": "offline fixture"}, {}
                return {"verdict": "FP", "sufficient": True, "missing_evidence": [],
                        "next_query": None, "reason_summary": "offline fixture"}, {}
        with patch("fpm_benchmark.revision_cli.make_client", return_value=Client()), \
             patch("fpm_benchmark.batch_codeql.subprocess.run", side_effect=self.synthetic_codeql_io) as io, \
             patch("fpm_benchmark.revision_runner.execute_template_query", side_effect=AssertionError("direct executor selected")):
            self.assertEqual(main(command), 0)
        self.assertGreaterEqual(io.call_count, 2)
        rows = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertTrue(all(r["operation"] == "SUPPRESS" for r in rows))
        policy = build_fp_policy(self.settings["fp_policy"], self.rows,
                                 template_manifest=self.manifest, method="queryfpm")
        for row in rows:
            self.assertEqual(len(row["query_history"]), 1)
            self.assertTrue(all(item["ok"] for item in policy.context.query_checks(row)))

    def test_actual_direct_executor_uses_unsupported_rendered_hash(self):
        manifest = self.prepare_actual_template()
        (self.database / "db-java").mkdir()
        parameters = {"file": "Case.java", "line": 1, "column": 1, "cwe": "CWE-079"}
        with patch("fpm_benchmark.codeql.subprocess.run", side_effect=self.synthetic_codeql_io):
            result = codeql.execute_template_query(
                codeql_bin="never-executed-codeql", database=self.database, manifest=manifest,
                template_id="find-bound-fixed-sink", parameters=parameters,
                template_root=self.manifest.parent, output_dir=self.root / "direct-fixture")
        policy = build_fp_policy(self.settings["fp_policy"], self.rows,
                                 template_manifest=self.manifest, method="queryfpm")
        evidence = {**self.rows[0], "query_history": [result]}
        check = policy.context.query_checks(evidence)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(check[0]["reason"], "query_provenance_mismatch")


if __name__ == "__main__":
    unittest.main()
