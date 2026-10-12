from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from fpm_benchmark.sarif import sarif_to_evidence


class SarifIdentityTest(unittest.TestCase):
    def test_same_line_different_columns_have_distinct_alert_ids(self) -> None:
        results = []
        for column in (4, 21):
            results.append(
                {
                    "ruleId": "java/path-injection",
                    "message": {"text": "Tainted path."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "Case.java"},
                                "region": {
                                    "startLine": 10,
                                    "startColumn": column,
                                    "endColumn": column + 4,
                                },
                            }
                        }
                    ],
                }
            )
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "java/path-injection",
                                    "properties": {"tags": ["external/cwe/cwe-022"]},
                                }
                            ]
                        }
                    },
                    "results": results,
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.sarif"
            path.write_text(json.dumps(sarif), encoding="utf-8")
            records = sarif_to_evidence(path)

        self.assertEqual(len(records), 2)
        self.assertEqual(len({record["alert_id"] for record in records}), 2)


if __name__ == "__main__":
    unittest.main()
