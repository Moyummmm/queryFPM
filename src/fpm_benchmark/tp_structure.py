"""Source-bound structural checks; model TP is not vulnerability proof."""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

FLOW_RULES = {
    'CWE-022': 'java/path-injection',
    'CWE-078': 'java/command-line-injection',
    'CWE-079': 'java/xss',
    'CWE-089': 'java/sql-injection',
    'CWE-090': 'java/ldap-injection',
    'CWE-643': 'java/xml/xpath-injection',
}


API_RULES = {
    'CWE-327': 'java/weak-cryptographic-algorithm',
    'CWE-330': 'java/insecure-randomness',
    'CWE-614': 'java/insecure-cookie',
}


VARIANTS = {'flow_strict', 'flow_or_api'}


UNVERIFIED = 'model_classified_unverified'


_IDENTIFIER = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')


_SHA256 = re.compile(r'^[a-f0-9]{64}$')


class ContextError(ValueError):
    """The trusted source or analysis provenance cannot be established."""


@dataclass
class TrustedContext:
    """Frozen, externally supplied trust anchors; never derive these from the model.

    source_hashes is a manifest of relative source paths and exact SHA-256 values;
    mask_java_comments is the frozen input-control lexer. The two analysis hashes
    identify the data source. These anchors do not prove source/sink feasibility.
    """
    source_root: Path
    source_hashes: dict[str, str]
    database_hash: str
    sarif_hash: str
    mask_java_comments: Callable[[str], str]

    def __post_init__(self) -> None:
        self.source_root = Path(self.source_root).resolve(strict=True)
        if not self.source_root.is_dir() or not isinstance(self.source_hashes, dict) or not self.source_hashes:
            raise ContextError('invalid trusted source snapshot')
        if not _SHA256.fullmatch(self.database_hash) or not _SHA256.fullmatch(self.sarif_hash):
            raise ContextError('invalid trusted analysis hash')
        if not callable(self.mask_java_comments):
            raise ContextError('a frozen Java comment masker is required')
        self._cache: dict[str, tuple[list[str], list[str]]] = {}

    def lines(self, name: Any) -> tuple[list[str], list[str]]:
        if not isinstance(name, str):raise ContextError('missing source filename')
        clean = name.replace('\\', '/')
        relative = PurePosixPath(clean)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != clean or relative.suffix != '.java':
            raise ContextError('source path must be a relative Java file')
        if clean not in self.source_hashes or not _SHA256.fullmatch(self.source_hashes[clean]):
            raise ContextError('source file absent from trusted manifest')
        if clean not in self._cache:
            try:
                target=(self.source_root/clean).resolve(strict=True)
                target.relative_to(self.source_root)
                data=target.read_bytes()
                if hashlib.sha256(data).hexdigest()!=self.source_hashes[clean]:
                    raise ContextError('source hash mismatch')
                text=data.decode('utf-8')
                masked=self.mask_java_comments(text)
            except (OSError, UnicodeError, ValueError) as exc:
                raise ContextError('trusted source file is unavailable or invalid') from exc
            if not isinstance(masked,str) or len(masked)!=len(text) or masked.count('\n')!=text.count('\n'):
                raise ContextError('comment masker does not preserve source offsets')
            self._cache[clean]=(text.splitlines(),masked.splitlines())
        return self._cache[clean]


def _valid_location(point: Any, trusted: TrustedContext) -> bool:
    if not isinstance(point,dict): return False
    name=point.get('file') or point.get('uri')
    line,column=point.get('start_line'),point.get('start_column')
    if type(line) is not int or line<1 or type(column) is not int or column<1:return False
    code=point.get('code')
    if not isinstance(code,str) or not code.strip() or '\n' in code or '\r' in code:return False
    try:
        raw,masked=trusted.lines(name)
    except ContextError:
        return False
    if line>len(raw) or line>len(masked):return False
    raw_line,masked_line=raw[line-1],masked[line-1]
    # CodeQL columns use UTF-16 code units, not Python code points.
    if column>len(raw_line.encode('utf-16-le'))//2+1:return False
    snippet=code.strip()
    start=raw_line.find(snippet)
    if start<0:return False
    # Must match a real, non-comment source span, not an injected comment.
    return bool(_IDENTIFIER.search(masked_line[start:start+len(snippet)]))


def _location_key(point: dict) -> tuple:
    return (str(point.get('file') or point.get('uri') or '').replace('\\','/'),
            point.get('start_line'),point.get('start_column'))


def _base_evidence(record: dict, trusted: TrustedContext) -> tuple[bool,str]:
    if not isinstance(record,dict) or not isinstance(record.get('alert_contract'),dict):return False,'missing_alert_contract'
    prov=record.get('analysis_provenance')
    if not isinstance(prov,dict) or prov.get('database_hash')!=trusted.database_hash or prov.get('sarif_sha256')!=trusted.sarif_hash:
        return False,'untrusted_analysis_provenance'
    if prov.get('language')!='java':return False,'unsupported_language'
    alert=record['alert_contract'];primary=alert.get('primary_location')
    if alert.get('tool')!='CodeQL' or not _valid_location(primary,trusted):return False,'unverified_alert_location'
    indices=alert.get('sarif_indices')
    if not isinstance(indices,dict) or type(indices.get('run')) is not int or type(indices.get('result')) is not int or indices['run']<0 or indices['result']<0:
        return False,'missing_sarif_reference'
    return True,'alert_location_present'


def _flow_structure(record: dict, trusted: TrustedContext) -> tuple[bool,str]:
    alert=record['alert_contract'];cwe=alert.get('cwe')
    if FLOW_RULES.get(cwe)!=alert.get('rule_id'):return False,'unsupported_flow_rule'
    trace=record.get('annotated_trace')
    if not isinstance(trace,list) or len(trace)<2:return False,'missing_source_sink_trace'
    if any(not isinstance(t,dict) or t.get('provenance')!='sarif.codeFlows' for t in trace):return False,'untrusted_trace_provenance'
    # One contiguous SARIF path only: concatenated or ambiguous paths abstain.
    if [t.get('step') for t in trace] != list(range(1,len(trace)+1)):
        return False,'noncontiguous_trace'
    if trace[0].get('role')!='SOURCE_CANDIDATE' or trace[-1].get('role')!='SINK_CANDIDATE':
        return False,'missing_ordered_source_sink'
    if any(t.get('role') in {'SOURCE_CANDIDATE','SINK_CANDIDATE'} for t in trace[1:-1]):
        return False,'ambiguous_multiple_sources_or_sinks'
    if _location_key(trace[-1])!=_location_key(alert['primary_location']):return False,'sink_not_bound_to_alert'
    if not all(_valid_location(t,trusted) for t in trace):return False,'unverified_trace_location'
    return True,'source_sink_trace_present_not_feasibility_proof'


def classify_evidence(record: dict, trusted: TrustedContext, variant: str) -> tuple[bool,str]:
    if variant not in VARIANTS:raise ValueError('unknown TP reporting variant')
    valid, reason = _base_evidence(record,trusted)
    if not valid:return False,reason
    alert=record['alert_contract'];cwe=alert.get('cwe')
    if cwe in FLOW_RULES:return _flow_structure(record,trusted)
    if variant=='flow_or_api' and API_RULES.get(cwe)==alert.get('rule_id'):
        # This is location-only context, not proof that the API use is vulnerable.
        return True,'api_alert_location_present_not_vulnerability_proof'
    return False,'unsupported_category_for_variant'


def early_tp_eligible(evidence: dict, candidate: dict, gate: dict, trusted: TrustedContext,
                      *, variant: str = 'flow_strict', infrastructure_errors: list | None = None) -> tuple[bool,str]:
    """Optional TP-only early KEEP proposal; never touches the FP gate.

    Callers must supply current controller-owned evidence and error state. This
    function does not modify evidence or execute a decision. An early stop may
    retain an FP the unchanged controller would later suppress.
    """
    if variant not in VARIANTS:raise ValueError('unknown TP reporting variant')
    if infrastructure_errors != []:return False,'infrastructure_or_unknown_error_state'
    if (not isinstance(candidate,dict) or candidate.get('verdict')!='TP' or candidate.get('sufficient') is not True
            or candidate.get('missing_evidence')!=[]):return False,'model_tp_incomplete'
    if not isinstance(gate,dict) or gate.get('authorized') is not False or gate.get('reason')!='semantic_tp_unverified':
        return False,'gate_state_not_semantic_tp_only'
    queries=evidence.get('query_history')
    if not isinstance(queries,list) or any(not isinstance(q,dict) or q.get('status')!='ok' for q in queries):
        return False,'incomplete_query_history'
    return classify_evidence(evidence,trusted,variant)
