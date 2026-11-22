"""Two actual CLI calls using only temporary DB fixtures and in-memory clients."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import test_fp_policy_cli as fixtures
from fpm_benchmark.revision_cli import main
from fpm_benchmark.database_lock import run_lock


PROPOSAL = {"verdict": "FP", "sufficient": True, "missing_evidence": [],
            "next_query": None, "reason_summary": "offline fixture"}


class DatabaseLockCliTests(unittest.TestCase):
    def fixture(self):
        case = fixtures.SourcePolicyCliTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.settings["workers"] = 1
        case.config.write_text(json.dumps(case.settings))
        return case

    @staticmethod
    def output_command(case, name):
        command = case.command.copy()
        command[command.index("--out") + 1] = str(case.root / name / "results/out.jsonl")
        return command

    def test_same_database_different_output_roots_reject_before_second_client(self):
        case = self.fixture()
        started, release = threading.Event(), threading.Event()
        calls = []
        class Client:
            def chat_json(self, messages, **kwargs):
                calls.append(1)
                started.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Test did not release held client")
                return dict(PROPOSAL), {}
        with patch("fpm_benchmark.revision_cli.make_client", return_value=Client()) as make_client:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(main, self.output_command(case, "jobA"))
                try:
                    self.assertTrue(started.wait(timeout=5))
                    with self.assertRaisesRegex(RuntimeError, "CodeQL database"):
                        main(self.output_command(case, "jobB"))
                    self.assertEqual(make_client.call_count, 1)
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=5), 0)
        self.assertEqual(len(calls), 2)
        self.assertTrue((case.database / ".fpm-experiment.lock").is_file())
        with run_lock(case.database, case.root / "after/output.jsonl"):
            pass

    def test_different_databases_run_concurrently(self):
        first, second = self.fixture(), self.fixture()
        barrier = threading.Barrier(2)
        calls = []
        class Client:
            def chat_json(self, messages, **kwargs):
                calls.append(threading.get_ident())
                barrier.wait(timeout=5)
                return dict(PROPOSAL), {}
        with patch("fpm_benchmark.revision_cli.make_client", return_value=Client()):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = [pool.submit(main, self.output_command(case, "job")) for case in (first, second)]
                self.assertEqual([result.result(timeout=8) for result in results], [0, 0])
        self.assertEqual(len(calls), 4)
        self.assertGreaterEqual(len(set(calls)), 2)

    def test_lock_is_held_before_database_fingerprint(self):
        case = self.fixture()
        with run_lock(case.database, case.root / "first/out.jsonl"):
            with patch("fpm_benchmark.revision_cli.database_fingerprint") as fingerprint, \
                 patch("fpm_benchmark.revision_cli.make_client") as client:
                with self.assertRaisesRegex(RuntimeError, "CodeQL database"):
                    main(self.output_command(case, "other"))
                fingerprint.assert_not_called()
                client.assert_not_called()

    def test_exception_releases_lock_without_unlinking_inode(self):
        case = self.fixture()
        path = case.database / ".fpm-experiment.lock"
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            with run_lock(case.database, case.root / "fail/out.jsonl"):
                inode = path.stat().st_ino
                raise RuntimeError("fixture failure")
        self.assertEqual(path.stat().st_ino, inode)
        with run_lock(case.database, case.root / "retry/out.jsonl"):
            self.assertEqual(path.stat().st_ino, inode)

    def enable_guard(self, case):
        case.settings["llm"].update({"base_url": "https://api.deepseek.com", "model": "deepseek-v4-flash",
            "thinking": "disabled", "use_environment_proxy": False,
            "input_token_guard": {"enabled": True, "assets_root": str(case.root / "missing-assets")}})
        case.config.write_text(json.dumps(case.settings))

    def test_enabled_guard_cannot_construct_client_before_database_lock(self):
        case = self.fixture()
        self.enable_guard(case)
        with run_lock(case.database, case.root / "held/out.jsonl"):
            with patch("fpm_benchmark.revision_cli._prepare_token_guard") as prepare, \
                 patch("fpm_benchmark.revision_cli.make_client") as client:
                with self.assertRaisesRegex(RuntimeError, "CodeQL database"):
                    main(self.output_command(case, "other"))
                prepare.assert_not_called()
                client.assert_not_called()

    def test_enabled_guard_follows_actual_database_and_source_preflight(self):
        case = self.fixture()
        self.enable_guard(case)
        (case.database / "codeql-database.yml").write_text("primaryLanguage: java\nname: changed\n")
        with patch("fpm_benchmark.revision_cli._prepare_token_guard") as prepare, \
             patch("fpm_benchmark.revision_cli.make_client") as client:
            with self.assertRaisesRegex(ValueError, "selected database snapshot"):
                main(self.output_command(case, "bad-db"))
            prepare.assert_not_called()
            client.assert_not_called()
        # Use a fresh DB fixture: extraction identity may include file metadata,
        # so rewriting old bytes is not assumed to restore the original hash.
        case = self.fixture()
        self.enable_guard(case)
        case.file.write_text("changed source")
        with patch("fpm_benchmark.revision_cli._prepare_token_guard") as prepare:
            with self.assertRaisesRegex(ValueError, "source preflight"):
                main(self.output_command(case, "bad-source"))
            prepare.assert_not_called()

    def test_client_construction_failure_writes_no_experiment_artifacts(self):
        case = self.fixture()
        with patch("fpm_benchmark.revision_cli.make_client", side_effect=RuntimeError("construction fixture")):
            with self.assertRaisesRegex(RuntimeError, "construction fixture"):
                main(case.command)
        self.assertFalse(case.output.exists())
        self.assertFalse(case.output.with_suffix(".manifest.json").exists())
        self.assertFalse(case.output.with_suffix(".records").exists())
        self.assertFalse(case.output.with_suffix(".summary.json").exists())

    def test_output_artifact_aliases_reject_before_second_client(self):
        aliases = ("out.ndjson", "out.jsonl.partial", "out.token_audit.jsonl",
                   "out.summary.json", "out.failed_attempts.fixture.jsonl", "other.jsonl")
        for alias in aliases:
            with self.subTest(alias=alias):
                first, second = self.fixture(), self.fixture()
                output = first.root / "shared/out.jsonl"
                first_command, second_command = first.command.copy(), second.command.copy()
                first_command[first_command.index("--out") + 1] = str(output)
                second_command[second_command.index("--out") + 1] = str(output.with_name(alias))
                entered, release = threading.Event(), threading.Event()
                def make_client(config):
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("Test did not release client preparation")
                    raise RuntimeError("stop before model requests")
                with patch("fpm_benchmark.revision_cli.make_client", side_effect=make_client) as client:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(main, first_command)
                        try:
                            self.assertTrue(entered.wait(timeout=5))
                            with self.assertRaisesRegex(RuntimeError, "Run output directory"):
                                main(second_command)
                            self.assertEqual(client.call_count, 1)
                            self.assertFalse(output.with_suffix(".records").exists())
                            self.assertFalse(output.with_suffix(".manifest.json").exists())
                        finally:
                            release.set()
                        with self.assertRaisesRegex(RuntimeError, "stop before model requests"):
                            future.result(timeout=5)
                # Rejection must release the second database lease.
                with run_lock(second.database, second.root / "fresh/out.jsonl"):
                    pass

    def test_output_directory_symlink_alias_shares_namespace(self):
        first, second = self.fixture(), self.fixture()
        directory = first.root / "shared"
        directory.mkdir()
        alias = first.root / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        with run_lock(first.database, directory / "out.jsonl"):
            with self.assertRaisesRegex(RuntimeError, "Run output directory"):
                with run_lock(second.database, alias / "other.jsonl"):
                    self.fail("Output-directory alias acquired a second namespace")

    def test_reserved_lock_outputs_and_record_subtrees_are_rejected(self):
        case = self.fixture()
        outputs = (case.root / ".fpm-output.lock", case.database / ".fpm-experiment.lock",
                   case.root / "out.jsonl.run.lock", case.root / "out.records/000000.json",
                   case.root / "queries/result/rendered.ql")
        for output in outputs:
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "reserved"):
                    with run_lock(case.database, output):
                        self.fail("Reserved artifact path acquired a run lock")
                self.assertFalse(output.exists())
        self.assertFalse((case.database / ".fpm-experiment.lock").exists())

    def test_output_symlink_to_database_lock_is_rejected_without_replacement(self):
        case = self.fixture()
        lock = case.database / ".fpm-experiment.lock"
        lock.write_text("existing lock bytes")
        inode = lock.stat().st_ino
        output = case.root / "alias.jsonl"
        output.symlink_to(lock)
        with self.assertRaisesRegex(ValueError, "coordination-lock"):
            with run_lock(case.database, output):
                self.fail("Output symlink to database lock was accepted")
        self.assertEqual(lock.read_text(), "existing lock bytes")
        self.assertEqual(lock.stat().st_ino, inode)
        self.assertTrue(output.is_symlink())

    def test_output_hardlink_to_coordination_lock_is_rejected(self):
        case = self.fixture()
        lock = case.root / ".fpm-output.lock"
        lock.write_text("existing namespace bytes")
        output = case.root / "alias.jsonl"
        output.hardlink_to(lock)
        with self.assertRaisesRegex(ValueError, "coordination-lock inode"):
            with run_lock(case.database, output):
                self.fail("Output hardlink to coordination inode was accepted")
        self.assertEqual(lock.read_text(), "existing namespace bytes")
        self.assertTrue(output.samefile(lock))

    def test_sidecar_alias_to_lock_and_lock_symlink_to_output_are_rejected(self):
        case = self.fixture()
        lock = case.database / ".fpm-experiment.lock"
        lock.write_text("database lock")
        output = case.root / "first.jsonl"
        output.with_suffix(".manifest.json").symlink_to(lock)
        with self.assertRaisesRegex(ValueError, "coordination-lock"):
            with run_lock(case.database, output):
                self.fail("Sidecar symlink to database lock was accepted")
        output = case.root / "second.jsonl"
        output.write_text("existing result")
        output.with_name(output.name + ".run.lock").symlink_to(output)
        with self.assertRaisesRegex(ValueError, "aliases a coordination-lock"):
            with run_lock(case.database, output):
                self.fail("Lock path resolving to output was accepted")
        self.assertEqual(output.read_text(), "existing result")

    def test_namespace_lock_preserves_existing_files_and_reuses_inode(self):
        case = self.fixture()
        output = case.root / "preserved/out.jsonl"
        output.parent.mkdir()
        output.write_text("prior result")
        legacy = output.with_name(output.name + ".run.lock")
        legacy.write_text("prior coordination bytes")
        legacy_inode = legacy.stat().st_ino
        with run_lock(case.database, output):
            namespace = output.parent / ".fpm-output.lock"
            namespace_inode = namespace.stat().st_ino
        with run_lock(case.database, output):
            self.assertEqual(namespace.stat().st_ino, namespace_inode)
            self.assertEqual(legacy.stat().st_ino, legacy_inode)
        self.assertEqual(output.read_text(), "prior result")
        self.assertEqual(legacy.read_text(), "prior coordination bytes")


if __name__ == "__main__":
    unittest.main()
