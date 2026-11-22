from __future__ import annotations

from typing import Any


SOURCE_SINK_CWES = {"CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-090", "CWE-643"}
API_MISUSE_CWES = {"CWE-327", "CWE-330"}
CONFIG_CWES = {"CWE-614"}
TRUST_BOUNDARY_CWES = {"CWE-501"}


PROFILES: dict[str, dict[str, Any]] = {
    "CWE-022": {
        "category": "source_sink",
        "name": "Path Traversal",
        "risk_patterns": ["user-controlled path reaches file API"],
        "safe_patterns": ["canonical path allowlist", "safe fixed base directory enforcement"],
        "non_sanitizers": ["URL decoding", "string trimming", "extension checks alone"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "validator_present",
        ],
    },
    "CWE-078": {
        "category": "source_sink",
        "name": "OS Command Injection",
        "risk_patterns": ["user-controlled value reaches command execution argument"],
        "safe_patterns": ["strict allowlist", "constant command without user-controlled shell syntax"],
        "non_sanitizers": ["encoding", "logging", "string trimming"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "sanitizer_present",
        ],
    },
    "CWE-079": {
        "category": "source_sink",
        "name": "Cross-site Scripting",
        "risk_patterns": ["user-controlled value written to HTML/JS response"],
        "safe_patterns": ["context-appropriate output encoding", "framework auto escaping"],
        "non_sanitizers": ["URL decoding", "HTML parsing without escaping"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "sanitizer_present",
            "framework_semantics_known",
        ],
    },
    "CWE-089": {
        "category": "source_sink",
        "name": "SQL Injection",
        "risk_patterns": ["user-controlled SQL syntax reaches query execution"],
        "safe_patterns": ["bind parameters", "PreparedStatement placeholders used correctly"],
        "non_sanitizers": ["URL decoding", "string concatenation wrappers", "escaping unknown to SQL"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "sink_argument_origin",
            "safe_api_usage",
        ],
    },
    "CWE-090": {
        "category": "source_sink",
        "name": "LDAP Injection",
        "risk_patterns": ["user-controlled value reaches LDAP filter/query string"],
        "safe_patterns": ["LDAP filter escaping", "allowlist validation"],
        "non_sanitizers": ["URL decoding", "string trimming"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "sanitizer_present",
        ],
    },
    "CWE-327": {
        "category": "api_misuse",
        "name": "Broken or Risky Crypto Algorithm",
        "risk_patterns": [
            "DES", "DES/CBC", "DESede", "DES/ECB",
            "MD5", "SHA1",
            "RC4", "RC2",
            "insecure SSL/TLS protocol (SSLv3, TLSv1.0)",
        ],
        "safe_patterns": [
            "Explicit AES/GCM/NoPadding; usage outside this narrow contract needs review",
            "SHA-256 or stronger",
            "HmacSHA256 or stronger",
            "Other algorithms require independently checked parameters",
        ],
        "non_sanitizers": [
            "Using a different cipher mode does not make a strong algorithm weak",
            "AES/ECB and implicit provider defaults do not establish safe usage",
        ],
        "sufficiency_checklist": ["api_identified", "argument_extracted", "argument_is_constant"],
    },
    "CWE-330": {
        "category": "api_misuse",
        "name": "Use of Insufficiently Random Values",
        "risk_patterns": ["java.util.Random used for security-sensitive value"],
        "safe_patterns": ["SecureRandom for tokens, session identifiers, keys"],
        "sufficiency_checklist": ["api_identified", "security_sensitive_use", "randomness_source_known"],
    },
    "CWE-501": {
        "category": "trust_boundary",
        "name": "Trust Boundary Violation",
        "risk_patterns": ["untrusted request data stored in trusted session/application state"],
        "safe_patterns": ["validated data crossing boundary", "server-generated trusted value"],
        "sufficiency_checklist": ["source_user_controlled", "trust_boundary_crossing", "validator_present"],
    },
    "CWE-614": {
        "category": "security_config",
        "name": "Sensitive Cookie Without Secure Flag",
        "risk_patterns": ["cookie created without secure flag"],
        "safe_patterns": ["setSecure(true)", "Secure attribute set by framework/config"],
        "sufficiency_checklist": ["cookie_created", "secure_flag_checked", "secure_flag_set"],
    },
    "CWE-643": {
        "category": "source_sink",
        "name": "XPath Injection",
        "risk_patterns": ["user-controlled value reaches XPath expression"],
        "safe_patterns": ["XPath variable binding", "strict allowlist"],
        "non_sanitizers": ["URL decoding", "string trimming"],
        "sufficiency_checklist": [
            "source_user_controlled",
            "sink_dangerous",
            "path_exists",
            "sanitizer_present",
        ],
    },
}


def profile_for(cwe: str | None) -> dict[str, Any]:
    if cwe and cwe in PROFILES:
        return PROFILES[cwe]
    return {
        "category": "unknown",
        "name": "Unknown",
        "risk_patterns": [],
        "safe_patterns": [],
        "non_sanitizers": [],
        "sufficiency_checklist": [],
    }


def default_slots(category: str) -> dict[str, str]:
    if category == "source_sink":
        return {
            "source_identified": "unknown",
            "sink_identified": "unknown",
            "path_exists": "unknown",
            "source_user_controlled": "unknown",
            "sink_dangerous": "unknown",
            "sink_argument_origin": "unknown",
            "sanitizer_present": "unknown",
            "validator_present": "unknown",
            "path_feasible": "unknown",
            "safe_api_usage": "unknown",
            "framework_semantics_known": "unknown",
            "constant_overwrite": "unknown",
            "nearby_sanitizer_found": "unknown",
            "nearby_validator_found": "unknown",
            "nearby_constant_assignment_found": "unknown",
            "call_context_required": "unknown",
            "call_context_resolved": "unknown",
            "call_context_constant_only": "unknown",
            "call_context_nonconstant_write": "unknown",
        }
    if category == "api_misuse":
        return {
            "api_identified": "unknown",
            "argument_extracted": "unknown",
            "argument_is_constant": "unknown",
            "known_weak_api_or_algorithm": "unknown",
            "known_strong_algorithm": "unknown",
            "security_sensitive_use": "unknown",
            "randomness_source_known": "unknown",
        }
    if category == "security_config":
        return {
            "cookie_created": "unknown",
            "secure_flag_checked": "unknown",
            "secure_flag_set": "unknown",
            "http_only_flag_set": "unknown",
            "same_site_flag_set": "unknown",
        }
    if category == "trust_boundary":
        return {
            "source_identified": "unknown",
            "source_user_controlled": "unknown",
            "trust_boundary_crossing": "unknown",
            "validator_present": "unknown",
            "trusted_state_target": "unknown",
            "session_argument_origin_checked": "unknown",
        }
    return {}
