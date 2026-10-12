from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from fpm_benchmark.batch_codeql import query_cache_key, render_batched_template, hash_codeql_database
from fpm_benchmark.codeql import summarize_bqrs_json
from fpm_benchmark.query_templates import find_template, load_template_manifest


class BatchCodeQLTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_template_manifest("templates/codeql/templates.json")

    def test_render_groups_locations_into_one_query(self) -> None:
        template = find_template(self.manifest, "find-constant-assignment-nearby")
        self.assertIsNotNone(template)
        requests = [
            {
                "request_id": "a",
                "template_id": template["id"],
                "parameters": {"file": "A.java", "line": 10},
            },
            {
                "request_id": "b",
                "template_id": template["id"],
                "parameters": {"file": "B.java", "line": 20},
            },
        ]

        rendered, window = render_batched_template(template, requests, "templates/codeql")

        self.assertNotIn("{{file}}", rendered)
        self.assertNotIn("{{line}}", rendered)
        self.assertIn('targetFile = "A.java" and targetLine = 10', rendered)
        self.assertIn('targetFile = "B.java" and targetLine = 20', rendered)
        self.assertIn("batchTarget(targetFile, targetLine)", rendered)
        self.assertEqual(window, (100, 120))

    def test_cache_key_is_parameter_order_independent(self) -> None:
        first = query_cache_key(
            database_hash="db",
            template_hash="template",
            parameters={"file": "A.java", "line": 10},
        )
        second = query_cache_key(
            database_hash="db",
            template_hash="template",
            parameters={"line": 10, "file": "A.java"},
        )
        self.assertEqual(first, second)

    def test_database_identity_ignores_query_strings_but_detects_extraction_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            base=root/'db-java/default';base.mkdir(parents=True)
            (root/'codeql-database.yml').write_text('finalised: true\n')
            relation=base/'expressions.rel';relation.write_bytes(b'extracted input')
            first=hash_codeql_database(root)
            strings=base/'strings/0';strings.mkdir(parents=True)
            (strings/'derived').write_bytes(b'query-generated constant')
            cache=base/'cache';cache.mkdir()
            (cache/'derived.rel').write_bytes(b'query relation')
            hash_codeql_database.cache_clear()
            self.assertEqual(first,hash_codeql_database(root))
            relation.write_bytes(b'changed extraction')
            hash_codeql_database.cache_clear()
            self.assertNotEqual(first,hash_codeql_database(root))

    def test_typed_location_predicate_keeps_exact_column_binding(self) -> None:
        template = find_template(self.manifest, "find-bound-ldap-literal")
        rendered, window = render_batched_template(template, [
            {"request_id": "a", "parameters": {"file": "A.java", "line": 12, "column": 9}},
            {"request_id": "b", "parameters": {"file": "A.java", "line": 12, "column": 20}},
        ], "templates/codeql")
        self.assertEqual(window, (0, 0))
        self.assertIn("literalPoint(arg, targetFile, targetLine, targetColumn)", rendered)
        self.assertIn("targetColumn = 9", rendered)
        self.assertIn("targetColumn = 20", rendered)
        self.assertNotIn("{{", rendered)

    def test_crypto_template_supports_batch_rendering(self) -> None:
        template = find_template(self.manifest, "find-crypto-algorithm")
        self.assertIsNotNone(template)

        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "crypto",
                    "template_id": template["id"],
                    "parameters": {"file": "Example.java", "line": 42, "column": 1},
                }
            ],
            "templates/codeql",
        )

        self.assertIn("batchTarget(targetFile, targetLine, targetColumn)", rendered)
        self.assertIn('"crypto_effective"', rendered)
        self.assertEqual(window, (0, 0))

    def test_randomness_template_covers_source_before_sink(self) -> None:
        template = find_template(self.manifest, "find-randomness-source")
        self.assertIsNotNone(template)

        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "random",
                    "template_id": template["id"],
                    "parameters": {"file": "Example.java", "line": 76},
                }
            ],
            "templates/codeql",
        )

        self.assertIn("java.util.Random", rendered)
        self.assertIn("java.security.SecureRandom", rendered)
        self.assertIn('getName() = "random"', rendered)
        self.assertIn('sourceKind = "java.lang.Math.random"', rendered)
        self.assertEqual(window, (80, 30))

    def test_session_origin_template_supports_batch_rendering(self) -> None:
        template = find_template(self.manifest, "find-session-attribute-origin")
        self.assertIsNotNone(template)
        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "session",
                    "template_id": template["id"],
                    "parameters": {"file": "Example.java", "line": 50},
                }
            ],
            "templates/codeql",
        )
        self.assertIn("session sink arguments", rendered)
        self.assertIn("producer return", rendered)
        self.assertIn("operationDefinesSinkArgument", rendered)
        self.assertIn("sameReceiver", rendered)
        self.assertIn('hasQualifiedName("javax.servlet.http", "HttpSession")', rendered)
        self.assertEqual(window, (100, 10))

    def test_static_field_call_context_template_supports_batch_rendering(self) -> None:
        template = find_template(self.manifest, "find-static-field-call-context")
        self.assertIsNotNone(template)
        rendered, window = render_batched_template(
            template,
            [
                {
                    "request_id": "context",
                    "template_id": template["id"],
                    "parameters": {
                        "file": "Sink.java",
                        "line": 50,
                        "field_name": "data",
                    },
                }
            ],
            "templates/codeql",
        )

        self.assertIn('field.getName() = "data"', rendered)
        self.assertIn("callerWritesFieldBeforeSink", rendered)
        self.assertIn("call-context evidence", rendered)
        self.assertIn("writer_calls_alert_sink=yes", rendered)
        self.assertNotIn("sinkCallable.getQualifiedName()", rendered)
        self.assertNotIn("sinkCall.getCaller().getQualifiedName()", rendered)
        self.assertEqual(window, (0, 0))

    def test_static_field_context_summary_deduplicates_ast_anchors(self) -> None:
        summary = summarize_bqrs_json(
            "find-static-field-call-context",
            {
                "#select": {
                    "tuples": [
                        [{"label": "first anchor"}, "same context fact"],
                        [{"label": "second anchor"}, "same context fact"],
                    ]
                }
            },
        )

        self.assertEqual(summary["tuple_count"], 2)
        self.assertEqual(len(summary["facts"]), 1)


if __name__ == "__main__":
    unittest.main()
