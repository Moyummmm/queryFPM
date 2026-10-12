import unittest
from fpm_benchmark.revision_statistics import paired_cluster_intervals,error_bounds
from fpm_benchmark.revision_cli import summarize

def row(key,truth,verdict,cluster):
    return {'alert_id':key,'ground_truth':{'alert_expected_vulnerable':truth},
      'decision':{'verdict':verdict},'dataset':{'cluster_id':cluster}}

class StatisticsTests(unittest.TestCase):
    def test_pairing_does_not_silently_drop_alerts(self):
        with self.assertRaises(ValueError):
            paired_cluster_intervals([row('1',True,'TP','p')],[])
    def test_shared_cluster_resampled_together(self):
        a=[row('1',True,'TP','p'),row('2',False,'FP','p')]
        b=[row('1',True,'TP','p'),row('2',False,'TP','p')]
        result=paired_cluster_intervals(a,b,replicates=20)
        self.assertEqual(result['clusters'],1)
        self.assertEqual(result['differences']['fprr']['cluster_percentile_95'],[1,1])
    def test_zero_errors_have_nonzero_upper_bound(self):
        result=error_bounds([row('1',True,'TP','p')])
        self.assertGreater(result['alert_wilson_95'][1],0)
        self.assertAlmostEqual(result['zero_error_cluster_upper_95'],.95)
    def test_replay_does_not_turn_failed_model_call_into_success(self):
        r=row('1',True,'INFRA_ERROR','p');r['operation']='KEEP'
        result=summarize([r])
        self.assertFalse(result['stages_same_trace_replay']['initial']['experiment_complete'])
