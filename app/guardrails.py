"""Guardrails: PII redaction, prompt-injection / jailbreak detection and output toxicity filtering. PII detection is regex-based and runs fully offline. Injection / jailbreak detection is heuristic: a weighted list of known patterns."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
PII_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}
def _luhn_ok(digits: str) -> bool:
    digits = re.sub(r"\D", "", digits)
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
def redact_pii(text: str) -> tuple[str, int]:
    redactions = 0
    redacted = text
    for entity, pattern in PII_PATTERNS.items():
        def _replace(match: re.Match) -> str:
            nonlocal redactions
            if entity == "CREDIT_CARD" and not _luhn_ok(match.group(0)):
                return match.group(0)
            redactions += 1
            return f"<{entity}>"
        redacted = pattern.sub(_replace, redacted)
    return redacted, redactions
def find_pii(text: str) -> list[str]:
    found: list[str] = []
    for entity, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            if entity == "CREDIT_CARD" and not _luhn_ok(match.group(0)):
                continue
            found.append(entity)
            break
    return found
INJECTION_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r"ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts?|rules|directions)", re.I), 2, "ignore_previous_instructions"),
    (re.compile(r"disregard (all |any |the |your )?(previous|prior|above|earlier)", re.I), 2, "disregard_instructions"),
    (re.compile(r"you are now (a|an|in)?\s*(dan|jailbreak|evil|unrestricted|uncensored|developer mode)", re.I), 2, "role_override"),
    (re.compile(r"\bdeveloper mode\b", re.I), 2, "developer_mode"),
    (re.compile(r"\bdo anything now\b|\bDAN\b", re.I), 2, "dan_jailbreak"),
    (re.compile(r"reveal (your |the )?(system prompt|instructions|hidden prompt|initial prompt)", re.I), 2, "system_prompt_extraction"),
    (re.compile(r"repeat (your |the )?(system prompt|instructions)", re.I), 2, "system_prompt_extraction"),
    (re.compile(r"pretend (you are|to be) (not |an? )?(an? )?(ai|assistant|chatgpt|language model)", re.I), 1, "pretend_not_ai"),
    (re.compile(r"act as (if you (are|were)|a) (different|unrestricted|evil)", re.I), 1, "role_override"),
    (re.compile(r"bypass (your |the )?(safety|filter|guardrail|content policy|restrictions)", re.I), 2, "bypass_safety"),
    (re.compile(r"override (your |the )?(safety|instructions|guidelines|rules)", re.I), 2, "override_instructions"),
    (re.compile(r"output (only|just) (the )?answer", re.I), 0, "benign_output_format"),
    (re.compile(r"forget (everything|all) (you|that)", re.I), 1, "forget_instructions"),
    (re.compile(r"new instructions?:", re.I), 1, "new_instructions"),
    (re.compile(r"\[SYSTEM\]|\[INST\]", re.I), 1, "fake_system_tag"),
    (re.compile(r"jailbreak", re.I), 1, "jailbreak_keyword"),
]
def detect_injection(text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    for pattern, weight, label in INJECTION_PATTERNS:
        if weight == 0:
            continue
        if pattern.search(text):
            score += weight
            matched.append(label)
    return score, matched
TOXIC_KEYWORDS: list[str] = ["kill yourself", "how to make a bomb", "how to build a bomb", "credit card numbers", "social security numbers",]
TOXIC_PATTERNS: list[re.Pattern] = [re.compile(re.escape(kw), re.I) for kw in TOXIC_KEYWORDS]
def detect_toxicity(text: str) -> list[str]:
    return [kw for kw, pat in zip(TOXIC_KEYWORDS, TOXIC_PATTERNS) if pat.search(text)]
@dataclass
class GuardrailResult:
    blocked: bool = False
    block_reason: str | None = None
    fired: list[str] = field(default_factory=list)
    redacted_text: str = ""
    redaction_count: int = 0
def run_pre_call_checks(text: str, policies) -> GuardrailResult:
    result = GuardrailResult(redacted_text=text)
    if policies.pii_redaction:
        redacted, count = redact_pii(text)
        result.redacted_text = redacted
        result.redaction_count = count
        if count:
            result.fired.append("pii_redaction")
    if policies.injection_detection or policies.jailbreak_detection:
        score, matched = detect_injection(text)
        if matched:
            result.fired.extend(f"injection:{label}" for label in matched)
        if score >= policies.injection_block_threshold:
            result.blocked = True
            result.block_reason = "prompt_injection"
            result.fired.append("prompt_injection_block")
    return result
def run_post_call_checks(text: str, policies) -> GuardrailResult:
    result = GuardrailResult(redacted_text=text)
    if policies.pii_redaction:
        redacted, count = redact_pii(text)
        result.redacted_text = redacted
        result.redaction_count = count
        if count:
            result.fired.append("response_pii_redaction")
            if policies.pii_block_response:
                result.blocked = True
                result.block_reason = "response_pii"
    if policies.toxicity_filter:
        hits = detect_toxicity(result.redacted_text)
        if hits:
            result.fired.append("toxicity_filter")
            result.blocked = True
            result.block_reason = "toxicity"
    return result
