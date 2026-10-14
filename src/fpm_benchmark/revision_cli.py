from __future__ import annotations
import argparse
import copy
import json
import os
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from .authorization import canonical_hash, authorization
from .metrics import compute_metrics
from .revision_runner import triage_record, make_client
from .utils import read_jsonl, write_jsonl
from .codeql import database_fingerprint

def main(argv=None):
    p=argparse.ArgumentParser(description="QueryFPM revised protocol runner")
    sub=p.add_subparsers(dest="command",required=True)
    run=sub.add_parser("run")
    for name in ("config","input","out"): run.add_argument("--"+name,required=True)
    run.add_argument("--method",choices=["queryfpm","matched_one_shot","zerofalse_style","direct_llm","llm4sa_style"],default="queryfpm")
    run.add_argument("--budget",type=int,choices=[0,1,2,3],default=2)
    run.add_argument("--guidance",choices=["base","generic"],default="generic")
    run.add_argument("--prefetch",action="store_true")
    run.add_argument("--replay")
    run.add_argument("--resume",action="store_true")
    run.add_argument("--limit",type=int)
    report=sub.add_parser("report"); report.add_argument("--input",required=True); report.add_argument("--out",required=True)
    args=p.parse_args(argv)
    if args.command=="report":
        rows=read_jsonl(args.input)
        report_data=summarize(rows)
        Path(args.out).write_text(json.dumps(report_data,indent=2),encoding="utf-8")
        return 0
    cfg=json.loads(Path(args.config).read_text(encoding="utf-8"))
    manifest=json.loads(Path(cfg["manifest"]).read_text(encoding="utf-8"))
    inputs=read_jsonl(args.input)
    if args.limit: inputs=inputs[:args.limit]
    ids=[r["alert_id"] for r in inputs]
    if len(set(ids))!=len(ids): raise ValueError("Duplicate alert IDs in input")
    if cfg.get("database"):
        db_hash=database_fingerprint(cfg["database"])
        if any(r.get("analysis_provenance",{}).get("database_hash") != db_hash for r in inputs):
            raise ValueError("Every revised alert input must be bound to the selected database snapshot")
    if not cfg["llm"].get("base_url","").startswith(("http://","https://")) or \
       not cfg["llm"].get("model") or "REQUIRES_" in cfg["llm"]["model"]:
        raise ValueError("Configure an actual model endpoint and model ID before running")
    source_root=Path(__file__).parent
    source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source_root.glob("*.py"))}
    template_hashes={t["file"]:hashlib.sha256((Path(cfg["manifest"]).parent/t["file"]).read_bytes()).hexdigest()
                     for t in manifest.get("templates",[])}
    frozen={"config":cfg,"manifest":manifest,"input_sha256":canonical_hash(inputs),
            "source_hashes":source_hashes,"template_hashes":template_hashes,
            "database_hash":database_fingerprint(cfg["database"]) if cfg.get("database") else None,
            "method":args.method,"budget":args.budget,"guidance":args.guidance,"prefetch":args.prefetch,
            "replay_hash":canonical_hash(read_jsonl(args.replay)) if args.replay else None}
    run_hash=canonical_hash(frozen)
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    meta=out.with_suffix(".manifest.json")
    records_dir = out.with_suffix('.records')
    completed=[]
    if out.exists() or records_dir.exists():
        if not args.resume: raise ValueError("Existing result is preserved; choose another output or use --resume")
        if not meta.exists() or json.loads(meta.read_text(encoding='utf-8')).get("run_hash")!=run_hash:
            raise ValueError("Resume configuration/input fingerprint mismatch")
        # Atomic per-alert files survive an interrupted JSONL append or checkpoint.
        prior = [json.loads(p.read_text(encoding='utf-8')) for p in sorted(records_dir.glob('*.json'))] \
                if records_dir.exists() else read_jsonl(out)
        if any(r.get('run_hash') != run_hash for r in prior):
            raise ValueError('Saved per-alert record has the wrong run fingerprint')
        if len({r["alert_id"] for r in prior}) != len(prior):
            raise ValueError("Duplicate alert IDs in resumed output")
        if any(r["alert_id"] not in ids for r in prior):
            raise ValueError("Resumed output contains an alert outside this condition")
        retry=[r for r in prior if r.get("decision",{}).get("verdict")=="INFRA_ERROR"]
        if retry:
            import datetime
            stamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            write_jsonl(out.with_name(out.stem+".failed_attempts."+stamp+".jsonl"),retry)
        completed=[r for r in prior if r.get("decision",{}).get("verdict")!="INFRA_ERROR"]
    elif args.resume: raise ValueError("No prior run to resume")
    records_dir.mkdir(exist_ok=True)
    if args.method=="queryfpm" and args.budget and not cfg.get("database") and not args.replay:
        raise ValueError("Full-pipeline condition requires an actual database")
    client=make_client(cfg)
    workers = cfg.get('workers', 1)
    if not isinstance(workers, int) or not 1 <= workers <= 32:
        raise ValueError('workers must be an integer in 1..32')
    runtime={**cfg["llm"],**cfg,"template_root":str(Path(cfg["manifest"]).parent),
             "query_output_dir":str(out.parent/"queries")}
    runtime['_query_mutex'] = threading.Lock()
    meta.write_text(json.dumps({"run_hash":run_hash,"frozen":frozen,"expected_records":len(inputs),
        "complete":False},indent=2),encoding="utf-8")
    replay=read_jsonl(args.replay) if args.replay else None
    done={r["alert_id"] for r in completed}
    # Rebuild the readable journal from durable records before adding fresh responses.
    write_jsonl(out, completed)
    # Lock protects this DB across distinct runs, including parallel baseline jobs.
    lock=out.parent.parent / ("db_"+canonical_hash(cfg.get("database"))[:16]+".lock")
    fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
    try:
        def adjudicate(r):
            result = triage_record(r,client=client,manifest=manifest,cfg=runtime,method=args.method,
                budget=args.budget,guidance=args.guidance=="generic",prefetch=args.prefetch,replay=replay)
            result['run_hash'] = run_hash
            return result
        positions = {key: i for i, key in enumerate(ids)}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {pool.submit(adjudicate, r): r['alert_id'] for r in inputs if r['alert_id'] not in done}
            for future in as_completed(pending):
                result = future.result()
                item = records_dir / (str(positions[result['alert_id']]).zfill(6) + '.json')
                temporary = item.with_suffix('.partial')
                temporary.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
                temporary.replace(item)
                completed.append(result)
                with out.open('a', encoding='utf-8') as journal:
                    journal.write(json.dumps(result, ensure_ascii=False) + '\n')
                if len(completed) % 25 == 0 or len(completed) == len(inputs):
                    print(f'completed {len(completed)}/{len(inputs)}', flush=True)
        completed.sort(key=lambda row: positions[row['alert_id']])
        temporary = out.with_suffix('.jsonl.partial')
        write_jsonl(temporary, completed)
        temporary.replace(out)
        summary=summarize(completed)
        summary["complete"]=(len(completed)==len(inputs) and summary["metrics"]["experiment_complete"])
        out.with_suffix(".summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
        meta.write_text(json.dumps({"run_hash":run_hash,"frozen":frozen,
            "expected_records":len(inputs),"complete":summary["complete"]},indent=2),encoding="utf-8")
    finally:
        os.close(fd); lock.unlink()
    return 0 if summary["complete"] else 2

def summarize(rows):
    routes={}; unmatched={}; costs={}; stages={}
    for r in rows:
        cwe=r.get("alert_contract",{}).get("cwe","UNKNOWN")
        route=r.get("authorization",{}).get("route")
        if r.get("operation")=="SUPPRESS":
            truth=r.get("ground_truth",{}).get("alert_expected_vulnerable")
            target=routes if truth is not None else unmatched
            key=f"{cwe}:{route}"; target[key]=target.get(key,0)+1
        for k,v in r.get("llm_usage_total",{}).items():
            if isinstance(v,int): costs[k]=costs.get(k,0)+v
    for stage in ("initial","initial_gated","final","final_gated"):
        copied=[]
        for r in rows:
            if r.get("decision",{}).get("verdict")=="INFRA_ERROR":
                copied.append(copy.deepcopy(r))
                continue
            if not r.get("llm_trace"): continue
            tr=r["llm_trace"][0 if stage.startswith("initial") else -1]
            candidate=tr["candidate"]
            verdict=candidate["verdict"] if candidate["sufficient"] else "UNKNOWN"
            if stage.endswith("gated") and not tr["controller_final"]: verdict="UNKNOWN"
            c=copy.deepcopy(r); c["decision"]={"verdict":verdict}; copied.append(c)
        stages[stage]=compute_metrics(copied)
    metrics=compute_metrics(rows)
    op=metrics["overall"]["operational"]
    removed=op["removed_fp"]+op["removed_tp"]
    route_total=sum(routes.values())+sum(unmatched.values())
    suppressed_total=sum(r.get("operation")=="SUPPRESS" for r in rows)
    if route_total!=suppressed_total: raise ValueError("Authorization route counts do not reconcile")
    return {"metrics":metrics,"stages_same_trace_replay":stages,"routes_labeled":routes,
            "routes_unmatched":unmatched,"usage":costs,
            "records":len(rows),"suppressed_total":suppressed_total,
            "python_retained_false_audit":[{"alert_id":r["alert_id"],
                "first_candidate":r.get("llm_trace",[{}])[0].get("candidate",{}).get("verdict") if r.get("llm_trace") else None,
                "final_candidate":r.get("candidate_decision",{}).get("verdict"),
                "final_verdict":r.get("decision",{}).get("verdict"),"stop_reason":r.get("stop_reason")}
                for r in rows if r.get("ground_truth",{}).get("alert_expected_vulnerable") is False
                and r.get("operation")=="KEEP"],
            "suppression_precision":op["removed_fp"]/removed if removed else None,
            "unavailable_queries":sum(q.get("status")=="unavailable" for r in rows for q in r.get("query_history",[])),
            "llm_seconds":sum(t.get("runtime_seconds",0) for r in rows for t in r.get("llm_trace",[])),
            "query_seconds":sum(q.get("runtime_seconds",0) for r in rows for q in r.get("query_history",[]))}

if __name__=="__main__": raise SystemExit(main())
