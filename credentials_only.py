"""Credential-only redaction for complete CVM log entries.

The transform preserves arbitrary text, payloads, request IDs, whitespace and
timestamps. It never drops or truncates an entry. Callers separately authenticate
the source and bind its identity; this module does not grant publish permission.
Expressions use RE2 syntax and one captured sensitive value for stage.replace.
"""
from __future__ import annotations

import json
import re

POLICY_VERSION = "credentials-only-v1"
SECRET_KEYS = (
    r"authorization|proxy[_-]authorization|"
    r"(?:[a-z0-9]+[_-])*api[_-]?key|"
    r"(?:[a-z0-9]+[_-])+(?:token)|"
    r"(?:[a-z0-9]+[_-])*(?:password|passwd|secret|private[_-]?key)|"
    r"client[_-]secret|access[_-]key|secret[_-]key|"
    r"x[_-]amz[_-](?:signature|credential|security[_-]token)|"
    r"x[_-]goog[_-](?:signature|credential)|signature"
)
KEY_PREFIX = r"(?i)\b(?:" + SECRET_KEYS + r")\\?[\"']?\s*[:=]\s*"
VALUE_PATTERNS = (
    r'\\"((?:[^"\\]|\\.)*?)\\"',
    r'"((?:\\.|[^"\\])*)"',
    r"'((?:\\.|[^'\\])*)'",
    r"([^\s,;}\]\[&\"']+)",
)
REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (r"(?s)(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)", "[REDACTED_PRIVATE_KEY]"),
    (r"(?s)(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*)", "[REDACTED_PRIVATE_KEY]"),
    (r"(?i)\b(?:Bearer|Basic)[ \t]+([a-z0-9._~+/=-]+)", "[REDACTED]"),
    *((KEY_PREFIX + value, "[REDACTED]") for value in VALUE_PATTERNS),
    # An unqualified numeric token counter is operational data. Uppercase TOKEN
    # and string-valued token assignments are conventional credentials.
    *((r"(?i)\btoken\\?[\"']?\s*[:=]\s*" + value, "[REDACTED]") for value in VALUE_PATTERNS[:3]),
    (r"\bTOKEN\\?[\"']?\s*[:=]\s*([^\s,;}\]\[&\"']+)", "[REDACTED]"),
    (r"(?i)\btoken\\?[\"']?\s*[:=]\s*([0-9]*[a-z_][^\s,;}\]\[&\"']*)", "[REDACTED]"),
    # URL query context identifies even a numeric token as a credential. Keep
    # every other query field and its separators unchanged.
    (r"(?i)[?&](?:" + SECRET_KEYS + r"|token|sig|key|auth|credential)=(\"[^\"]*\"|[^&#\s\"'<>]+)", "[REDACTED]"),
    *((r"(?i)\b(?:cookie|set[_-]cookie)\\?[\"']?\s*[:=]\s*" + value, "[REDACTED_COOKIE]") for value in VALUE_PATTERNS[:3]),
    (r"(?i)\b(?:cookie|set[_-]cookie)\\?[\"']?\s*[:=]\s*([^\s;\"']+(?:;[ \t]*[^=;\s\"']+=[^;\s\"']*)*;?)", "[REDACTED_COOKIE]"),
    (r"(?i)[a-z][a-z0-9+.-]{0,31}://([^/@\s]+)@", "[REDACTED]"),
    (r"\b(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b", "[REDACTED_JWT]"),
    (r"\b(sk-[a-zA-Z0-9_-]{12,}|gh[pousr]_[a-zA-Z0-9_]{12,}|github_pat_[a-zA-Z0-9_]{12,}|AKIA[A-Z0-9]{16})\b", "[REDACTED_KEY]"),
)


def alloy_sanitize_stages(*, indent: str = "  ") -> str:
    """Render redaction only: no body, size, format or rate drops."""
    if indent.strip():
        raise ValueError("indent may contain whitespace only")
    blocks = []
    for expression, replacement in REPLACEMENTS:
        blocks.append("stage.replace {\n  expression = " + json.dumps(expression) +
                      "\n  replace = " + json.dumps(replacement) + "\n}")
    return "\n".join("\n".join(indent + line for line in block.splitlines())
                     for block in blocks)


def sanitize_for_test(text: str) -> str:
    """Reference transform; native Alloy tests establish deployed behavior."""
    for expression, replacement in REPLACEMENTS:
        def replace(match: re.Match[str], value: str = replacement) -> str:
            start, end = match.span(1)
            return match.group(0)[:start-match.start()] + value + match.group(0)[end-match.start():]
        text = re.sub(expression, replace, text)
    return text


def synthetic_fixture_cases() -> list[dict]:
    """No real credentials or production bodies are used by these fixtures."""
    return [
        {"id":"plain", "line":"unknown customer body payload={\"content\":\"KEEP_PAYLOAD\"} request_id=keep-request-42 token=120832 prompt_tokens=8192 completion_tokens=256", "exact":True},
        {"id":"query", "line":"GET https://example.invalid/api?page=2&content=KEEP_TEXT&request_id=keep-query-42&count=99 status=200", "exact":True},
        {"id":"multiline", "line":"unrecognized first line\n  payload: KEEP_MULTILINE\n{\"content\":\"KEEP_JSON\"}\nTraceback fake frame\nlast line\n", "exact":True},
        {"id":"marker_collision", "line":"PHALA_LOG_FRAGMENT_V1 "+"a"*64+" 0 1 1730000000000000000\n{\"fragment_body\":\"KEEP_MARKER_COLLISION\"}", "exact":True},
        {"id":"ansi", "line":"\x1b[31mraw style\x1b[0m \tKEEP_TAB\n\n", "exact":True},
        {"id":"counter", "line":"Decode batch. token=123456 token: 1234 #token: 120832 completion_tokens=8192 token usage: 0.25", "exact":True},
        {"id":"secret", "line":"Authorization: Bearer FAKE_BEARER_913 Basic RkFLRV9CQVNJQ184NzY= api_key=FAKE_API_861 password=\"FAKE PASS !\" token=9FAKE_TOKEN_126 access_token=123456 status=503 request_id=keep-mixed-8 payload=KEEP_MIXED", "absent":["FAKE_BEARER_913","RkFLRV9CQVNJQ184NzY=","FAKE_API_861","FAKE PASS !","9FAKE_TOKEN_126","123456"], "contains":["status=503","request_id=keep-mixed-8","payload=KEEP_MIXED"]},
        {"id":"escaped", "line":r'json {\"api_key\":\"FAKE QUOTED ! 87\",\"token\":\"FAKE TOKEN 78!\",\"content\":\"KEEP_ESCAPED\"} status=400', "absent":["FAKE QUOTED ! 87","FAKE TOKEN 78!"], "contains":[r'\"content\":\"KEEP_ESCAPED\"',"status=400"]},
        {"id":"json_valid", "line":'{"password":"FAKE JSON VALUE !","cookie":"session=FAKE_COOKIE_89","token":"123456","content":{"keep":[1,2,"unchanged"]},"request_id":"keep-json-id"}', "absent":["FAKE JSON VALUE !","FAKE_COOKIE_89","123456"], "contains":['"password":"[REDACTED]"','"content":{"keep":[1,2,"unchanged"]}','"request_id":"keep-json-id"']},
        {"id":"cookie", "line":"Cookie: session=FAKE_SESSION_78; csrf=FAKE_CSRF_19 status=503 elapsed_ms=32 payload=KEEP_COOKIE_SUFFIX", "absent":["FAKE_SESSION_78","FAKE_CSRF_19"], "contains":["status=503 elapsed_ms=32 payload=KEEP_COOKIE_SUFFIX"]},
        {"id":"url_secret", "line":"https://alice:FAKE_USERINFO_123@example.invalid/a?page=2&token=123456&password=98765&X-Amz-Signature=FAKE_SIG_783&content=KEEP_QUERY status=503", "absent":["alice","FAKE_USERINFO_123","123456","98765","FAKE_SIG_783"], "contains":["example.invalid/a?page=2&token=","&content=KEEP_QUERY status=503"]},
        {"id":"key", "line":"before\n-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_MATERIAL_691\n-----END PRIVATE KEY-----\nafter payload=KEEP_AFTER_KEY", "absent":["FAKE_PRIVATE_MATERIAL_691"], "contains":["before\n[REDACTED_PRIVATE_KEY]\nafter payload=KEEP_AFTER_KEY"]},
        {"id":"jwt", "line":"payload=KEEP_JWT eyJhbGciOiJub25lIn0.eyJzdWIiOiJGQUtFIn0.c2lnbmF0dXJl status=401", "absent":["eyJhbGciOiJub25lIn0"], "contains":["payload=KEEP_JWT", "status=401"]},
    ]
