"""Conservative source-bound check for semantic CWE-327 TP proposals.

No property file is read or interpreted as runtime configuration. Dynamic
algorithm expressions abstain unless the ORIGINAL gate already established a
bound weak-crypto fact. This checker authorizes no suppression.
"""
from __future__ import annotations

from .java_source_lexer import _java_units, InputControlError
from .authorization import classify_algorithm
from .tp_structure import TrustedContext, ContextError


def _tokens(text: str) -> list[tuple[str,str,int,int,int,int]]:
    """Tokenize enough Java to find direct literals; reject ambiguous escapes."""
    units=_java_units(text)
    chars=[u[0] for u in units]
    for char,start,end in units:
        if char in '\r\n' and text[start:end] not in {'\r','\n'}:
            raise ValueError('Unicode-generated newline changes source-line semantics')
    out=[];i=0;n=len(chars)
    def line(pos):return text.count('\n',0,units[pos][1])+1
    def column(pos):
        start=units[pos][1];begin=text.rfind('\n',0,start)+1
        return len(text[begin:start].encode('utf-16-le'))//2+1
    def token(kind,value,start,end):
        end_offset=units[end-1][2]
        end_line=text.count('\n',0,end_offset)+1
        begin=text.rfind('\n',0,end_offset)+1
        end_column=len(text[begin:end_offset].encode('utf-16-le'))//2+1
        return (kind,value,line(start),column(start),end_line,end_column)
    while i<n:
        c=chars[i]
        if c.isspace():i+=1;continue
        if c=='"':
            start=i
            if chars[i:i+3]==['"','"','"']:
                i+=3
                while i<n and chars[i:i+3]!=['"','"','"']:
                    i+=2 if chars[i]=='\\' else 1
                if i>=n:raise ValueError('unclosed text block')
                i+=3;out.append(token('TEXTBLOCK','',start,i));continue
            i+=1;contents=[];escaped=False
            while i<n and chars[i]!='"':
                if chars[i] in '\r\n':raise ValueError('newline in string literal')
                if chars[i]=='\\':
                    escaped=True;i+=2;continue
                contents.append(chars[i]);i+=1
            if i>=n:raise ValueError('unclosed string literal')
            i+=1;out.append(token('ESCAPED_STRING' if escaped else 'STRING',''.join(contents),start,i));continue
        if c=="'":
            start=i;i+=1
            while i<n and chars[i]!="'":i+=2 if chars[i]=='\\' else 1
            if i>=n:raise ValueError('unclosed char literal')
            i+=1;out.append(token('CHAR','',start,i));continue
        if c.isalpha() or c in '_$':
            start=i;i+=1
            while i<n and (chars[i].isalnum() or chars[i] in '_$'):i+=1
            out.append(token('IDENT',''.join(chars[start:i]),start,i));continue
        out.append(token('PUNCT',c,i,i+1));i+=1
    return out


def direct_weak_literal(evidence: dict, trusted: TrustedContext) -> tuple[bool,str]:
    """Require an unambiguous direct weak literal at the reported API line."""
    primary=evidence.get('alert_contract',{}).get('primary_location',{})
    filename=primary.get('file') or primary.get('uri');line=primary.get('start_line')
    if not isinstance(filename,str) or type(line) is not int or line<1:
        return False,'crypto_alert_location_missing'
    try:
        _,masked_lines=trusted.lines(filename)
        tokens=_tokens('\n'.join(masked_lines))
    except (ContextError,InputControlError,ValueError):
        return False,'crypto_source_unavailable_or_ambiguous'
    matches=[i for i,t in enumerate(tokens) if t[:3]==('IDENT','getInstance',line)]
    if len(matches)!=1:return False,'crypto_call_missing_or_ambiguous'
    i=matches[0]
    start_column=primary.get('start_column');end_column=primary.get('end_column');end_line=primary.get('end_line')
    if end_line is None:end_line=line
    if (type(start_column) is not int or start_column<1 or type(end_line) is not int or end_line<line
            or type(end_column) is not int or end_column<1):
        return False,'crypto_reported_region_incomplete'
    if end_line>len(masked_lines) or end_column>len(masked_lines[end_line-1].encode('utf-16-le'))//2+1:
        return False,'crypto_reported_region_outside_source'
    if (end_line,end_column)<=(line,start_column) or tokens[i][3]<start_column:
        return False,'crypto_call_outside_reported_region'
    if (tokens[i][2],tokens[i][3]) >= (end_line,end_column):
        return False,'crypto_call_outside_reported_region'
    if i<1 or i+3>=len(tokens) or tokens[i-1][1]!='.' or tokens[i+1][1]!='(':
        return False,'crypto_call_not_direct'
    literal,following=tokens[i+2],tokens[i+3]
    if literal[0]!='STRING' or following[1] not in {')',','}:
        return False,'crypto_effective_algorithm_unbound'
    if (literal[4],literal[5])>(end_line,end_column) or (following[4],following[5])>(end_line,end_column):
        return False,'crypto_argument_outside_reported_region'
    if classify_algorithm(literal[1])!='weak':
        return False,'crypto_direct_literal_not_classified_weak'
    return True,'crypto_direct_weak_literal_bound_not_runtime_proof'
