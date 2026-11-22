"""Paired alert comparisons with test/project cluster bootstrap and zero-error bounds."""
from __future__ import annotations
import math
import random
from collections import defaultdict


def wilson(successes, trials, z=1.959963984540054):
    if not trials: return None
    p=successes/trials; den=1+z*z/trials
    centre=(p+z*z/(2*trials))/den
    half=z*math.sqrt(p*(1-p)/trials+z*z/(4*trials*trials))/den
    return [max(0,centre-half),min(1,centre+half)]


def cluster_id(row):
    return (row.get("dataset",{}).get("cluster_id") or row.get("project_id") or
            row.get("ground_truth",{}).get("benchmark_test") or row["alert_id"])


def counts(rows):
    c=[0,0,0,0]  # true alerts, false alerts, removed true, removed false
    for r in rows:
        truth=r.get("ground_truth",{}).get("alert_expected_vulnerable")
        if truth is None: continue
        suppressed=r.get("decision",{}).get("verdict")=="FP"
        c[0 if truth else 1]+=1
        if suppressed:c[2 if truth else 3]+=1
    return c


def rates(c):
    nt,nf,rt,rf=c; kt=nt-rt; kf=nf-rf
    precision=kt/(kt+kf) if kt+kf else None
    tpr=kt/nt if nt else None; fprr=rf/nf if nf else None
    f1=2*kt/(2*kt+kf+rt) if 2*kt+kf+rt else None
    return {"tpr":tpr,"fprr":fprr,"f1":f1,
            "suppression_precision":rf/(rf+rt) if rf+rt else None}


def paired_cluster_intervals(left,right,*,replicates=2000,seed=20261009):
    """Differences left minus right; resample common clusters together, never alerts separately."""
    a={r["alert_id"]:r for r in left}; b={r["alert_id"]:r for r in right}
    if len(a)!=len(left) or len(b)!=len(right) or a.keys()!=b.keys():
        raise ValueError("Pairing requires unique, identical alert sets")
    if any(r.get("decision",{}).get("verdict")=="INFRA_ERROR" for r in left+right):
        raise ValueError("Infrastructure failures invalidate paired comparison")
    groups=defaultdict(lambda:[[],[]])
    for key,r in a.items():
        other=b[key]
        if r.get("ground_truth")!=other.get("ground_truth") or cluster_id(r)!=cluster_id(other):
            raise ValueError("Pairing has inconsistent labels or clusters")
        groups[cluster_id(r)][0].append(r); groups[cluster_id(r)][1].append(other)
    clustered=[(counts(x),counts(y)) for x,y in groups.values()]
    if not clustered:raise ValueError("Empty paired set")
    rng=random.Random(seed); samples=defaultdict(list)
    for _ in range(replicates):
        ca=[0]*4;cb=[0]*4
        for index in rng.choices(range(len(clustered)),k=len(clustered)):
            x,y=clustered[index]
            ca=[u+v for u,v in zip(ca,x)];cb=[u+v for u,v in zip(cb,y)]
        ra,rb=rates(ca),rates(cb)
        for k in ra:
            if ra[k] is not None and rb[k] is not None:samples[k].append(ra[k]-rb[k])
    def interval(xs):
        if not xs:return None
        xs=sorted(xs);return [xs[int((len(xs)-1)*.025)],xs[int((len(xs)-1)*.975)]]
    ra,rb=rates(counts(left)),rates(counts(right))
    return {"estimand":"left_minus_right","clusters":len(clustered),"alerts":len(left),
       "seed":seed,"bootstrap_replicates":replicates,
       "differences":{k:{"observed":ra[k]-rb[k] if ra[k] is not None and rb[k] is not None else None,
                          "cluster_percentile_95":interval(samples[k])} for k in ra},
       "zero_error_note":"A degenerate bootstrap interval is not a guarantee of zero future errors."}


def error_bounds(rows):
    true=[r for r in rows if r.get("ground_truth",{}).get("alert_expected_vulnerable") is True]
    errors=sum(r.get("decision",{}).get("verdict")=="FP" for r in true)
    exposed={cluster_id(r) for r in true}
    affected={cluster_id(r) for r in true if r.get("decision",{}).get("verdict")=="FP"}
    return {"true_alerts":len(true),"removed_tp":errors,"alert_wilson_95":wilson(errors,len(true)),
      "exposed_clusters":len(exposed),"clusters_with_error":len(affected),
      "zero_error_cluster_upper_95":1-.05**(1/len(exposed)) if exposed and not affected else None,
      "assumption":"Wilson treats alerts as independent; the zero-error bound treats clusters as independent."}
