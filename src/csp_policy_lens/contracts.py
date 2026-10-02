"""Finite offline evidence. Reports contain positions and digests, not policy text."""

import json
from dataclasses import asdict, dataclass, fields
from hashlib import sha256


class Incomplete(ValueError):
    """Constant reason for incomplete analysis."""


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 1048576
    json_nodes: int = 20000
    json_depth: int = 32
    headers: int = 32
    policies: int = 64
    policy_bytes: int = 32768
    directives: int = 512
    tokens: int = 8192
    token_bytes: int = 4096
    findings: int = 512
    report_bytes: int = 524288

    def validate(self):
        maximum = Limits()
        for f in fields(self):
            value = getattr(self, f.name)
            if type(value) is not int or not 1 <= value <= getattr(maximum, f.name):
                raise ValueError("invalid_limits")
        if self.report_bytes < 2048:
            raise ValueError("invalid_limits")


def digest(text):
    return sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class Evidence:
    def __init__(self, limits):
        self.limits = limits
        self.counts = {"headers": 0, "policies": 0, "directives": 0, "tokens": 0}
        self.findings = []
        self.open = False
        self.fail = False
        self.violation_count = 0

    def charge(self, kind):
        self.counts[kind] += 1
        if self.counts[kind] > getattr(self.limits, kind):
            raise Incomplete("budget_" + kind)

    def emit(self, code, status="INFO", **where):
        self.open |= status == "OPEN"
        self.fail |= status == "FAIL"
        self.violation_count += status == "FAIL"
        if len(self.findings) >= self.limits.findings:
            self.open = True
            raise Incomplete("budget_findings")
        self.findings.append({"code": code, "status": status, **where})

    def finish(self, data, policies, models):
        report = {
            "schema_version": 1,
            "rule_version": "csp-policy-lens-1",
            "status": "FAIL" if self.fail else "OPEN" if self.open else "PASS",
            "analysis_completeness": "INCOMPLETE" if self.open else "COMPLETE",
            "input_sha256": sha256(data).hexdigest()
            if len(data) <= self.limits.input_bytes
            else None,
            "input_bytes": len(data),
            "counts": self.counts,
            "limits": asdict(self.limits),
            "known_violation_count": self.violation_count,
            "policies": policies,
            "combined_enforced_models": models,
            "findings": self.findings,
            "external": {
                "actual_headers": "OPEN",
                "browser_enforcement": "OPEN",
                "nonce_entropy_and_reuse": "OPEN",
                "script_or_policy_code": "OPEN",
                "url_and_redirect_matching": "OPEN",
                "xss_elimination": "OPEN",
                "cvp_eligibility": "OPEN",
                "trusted_types_api_default_name_uniqueness": "OPEN",
            },
        }
        if (
            len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode())
            > self.limits.report_bytes
        ):
            report["status"] = "FAIL" if self.fail else "OPEN"
            report["analysis_completeness"] = "INCOMPLETE"
            report["policies"] = []
            report["combined_enforced_models"] = []
            report["findings"] = [{"code": "budget_report", "status": "OPEN"}]
        return report
