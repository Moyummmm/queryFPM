"""Dual-branch decision gate: semantic TP/KEEP, original FP authorization.

For an FP or UNKNOWN candidate the returned gate is exactly the frozen
authorization result. Source comments, model prose and confidence can never
create trusted safety facts or authorize suppression.
"""
from __future__ import annotations

import copy
from typing import Any
from .authorization import authorization
from .fp_policy import strict_fp_reference
from .tp_structure import TrustedContext, UNVERIFIED, early_tp_eligible
from .tp_crypto_guard import direct_weak_literal

VERSION='dual-tp-semantic-v2.1'


def evaluate(evidence: dict, candidate: dict, *, trusted_context: TrustedContext,
             variant: str, infrastructure_errors: list,
             minimum_successful_queries_before_tp: int = 0, query_budget: int = 2,
             confirmed_action_exhaustion: bool = False) -> dict[str,Any]:
    """Produce a finalization gate without conflating TP and suppression safety."""
    if not isinstance(candidate,dict) or candidate.get('verdict') not in {'TP','FP','UNKNOWN'}:
        raise ValueError('normalized candidate is required')
    verdict=candidate['verdict']
    original=authorization(evidence,verdict)
    # Preserve the FP/UNKNOWN gate, including every field and safety check.
    if verdict!='TP':return original
    if not isinstance(trusted_context,TrustedContext):raise ValueError('trusted static evidence context is required')
    if variant not in {'flow_strict','flow_or_api'}:raise ValueError('unknown TP evidence variant')
    if not isinstance(infrastructure_errors,list):raise ValueError('explicit infrastructure error state is required')
    if type(minimum_successful_queries_before_tp) is not int or minimum_successful_queries_before_tp not in {0,1,2}:
        raise ValueError('minimum successful TP queries must be 0, 1 or 2')
    if type(query_budget) is not int or query_budget not in {0,1,2,3}:
        raise ValueError('query budget must be 0, 1, 2 or 3')
    if type(confirmed_action_exhaustion) is not bool:
        raise ValueError('controller-confirmed action exhaustion must be a boolean')

    base={**original,'authorized':False,'gate_policy':VERSION,'gate_branch':'TP',
          'security_operation':'KEEP','original_gate':copy.deepcopy(original),
          'verification':'not_classified'}
    if infrastructure_errors:
        return {**base,'reason':'infrastructure_failure'}
    queries=evidence.get('query_history')
    if not isinstance(queries,list) or any(not isinstance(q,dict) or q.get('status')!='ok' for q in queries):
        return {**base,'reason':'incomplete_query_history'}
    if candidate.get('sufficient') is not True or candidate.get('missing_evidence')!=[]:
        return {**base,'reason':'model_tp_incomplete'}
    safety_gate=strict_fp_reference(evidence,'FP')
    base['original_fp_gate']=copy.deepcopy(safety_gate)
    if safety_gate.get('authorized') is True:
        return {**base,'reason':'tp_conflicts_with_bound_safety_certificate'}
    if original.get('authorized') is True:
        # An already bound weak-algorithm certificate is an independent
        # original gate authorization; do not delay it for a semantic threshold.
        return {**base,'authorized':True,'route':original['route'],'fact_ids':original['fact_ids'],
                'reason':original['reason'],'verification':'bound_weak_algorithm_fact_not_vulnerability_proof',
                'successful_queries':len(queries),'minimum_successful_queries_before_tp':minimum_successful_queries_before_tp,
                'query_budget':query_budget}
    eligible,reason=early_tp_eligible(evidence,candidate,original,trusted_context,
                                      variant=variant,infrastructure_errors=infrastructure_errors)
    if not eligible:return {**base,'tp_structure_reason':reason}
    if evidence.get('alert_contract',{}).get('cwe')=='CWE-327':
        literal_ok,literal_reason=direct_weak_literal(evidence,trusted_context)
        if not literal_ok:
            return {**base,'reason':'crypto_effective_algorithm_unbound',
                    'tp_structure_reason':literal_reason}
        base['crypto_literal_evidence']=literal_reason
    base.update({'tp_structure_reason':reason,'successful_queries':len(queries),
                 'minimum_successful_queries_before_tp':minimum_successful_queries_before_tp,
                 'query_budget':query_budget})
    if len(queries)<minimum_successful_queries_before_tp and len(queries)<query_budget:
        if not confirmed_action_exhaustion or not queries:
            return {**base,'reason':'tp_wait_for_evidence'}
        base['evidence_actions_exhausted']=True
    return {**base,'authorized':True,'route':'semantic_tp_structural',
            'reason':'model_tp_with_structural_evidence','verification':UNVERIFIED,
            'interpretation':'Model TP classification; static structure is not proof of exploitability.'}
