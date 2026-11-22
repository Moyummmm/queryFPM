import unittest
from fpm_benchmark.cli import (_decision_is_final, _gate_observation,
    _controller_next_query, _update_slots_from_query, _normalize_query_request)
from test_revision import evidence, result, attach

class RevisedControllerBridgeTest(unittest.TestCase):
    def test_candidate_alone_is_not_final(self):
        self.assertFalse(_decision_is_final({"verdict":"FP","sufficient":True,"confidence":"high"}))

    def test_sarif_tp_slots_do_not_finalize(self):
        self.assertFalse(_decision_is_final({"verdict":"TP","sufficient":True},evidence()))

    def test_verified_bound_fp_is_final_without_confidence(self):
        e=evidence();attach(e,result())
        self.assertTrue(_decision_is_final({"verdict":"FP","sufficient":True},e))

    def test_nearby_context_never_sets_safety_slot(self):
        e=evidence();e["evidence_slots"]["sanitizer_present"]="unknown"
        _update_slots_from_query(e,{"template_id":"find-xss-encoder-nearby","status":"ok",
                                    "summary":{"tuple_count":1}})
        self.assertEqual(e["evidence_slots"]["nearby_sanitizer_found"],"yes")
        self.assertEqual(e["evidence_slots"]["sanitizer_present"],"unknown")
        self.assertFalse(_decision_is_final({"verdict":"FP","sufficient":True},e))

    def test_empty_and_failed_observations_are_distinct(self):
        for status,state in [("ok","checked_none"),("failed","error"),("unavailable","unknown")]:
            e=evidence();_update_slots_from_query(e,{"template_id":"find-validator-or-guard",
                          "status":status,"summary":{"tuple_count":0}})
            self.assertEqual(e["evidence_slots"]["nearby_validator_found"],state)
            self.assertFalse(_decision_is_final({"verdict":"FP","sufficient":True},e))

    def test_location_parameters_override_model(self):
        m={"templates":[{"id":"find-sql-parameterization","parameters":["file","line"]}]}
        q=_normalize_query_request({"template_id":"find-sql-parameterization",
                "parameters":{"file":"Other.java","line":100}},evidence(),m)
        self.assertEqual(q["parameters"],{"file":"Case.java","line":10})

    def test_gate_observation_contains_route_and_policy(self):
        e=evidence();attach(e,result());g=_gate_observation({"verdict":"FP","sufficient":True},e)
        self.assertEqual(g["route"],"sql_parameterized")
        self.assertTrue(g["controller_final"])
        self.assertEqual(g["policy_version"],"explicit-bound-v3")

if __name__=="__main__":unittest.main()
