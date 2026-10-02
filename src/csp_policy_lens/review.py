"""Public immutable-byte and local-file workflow, with no browser/network calls."""

from .contracts import Evidence, Incomplete, Limits
from .files import read_regular
from .input import decode
from .model import combined, model_policy
from .parser import parse_header


def review_bytes(data, *, limits=None, versions=(2, 3)):
    if type(data) is not bytes:
        raise ValueError("bytes_required")
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise ValueError("limits_required")
    limits.validate()
    if (
        type(versions) is not tuple
        or not versions
        or any(type(v) is not int or v not in {2, 3} for v in versions)
        or len(set(versions)) != len(versions)
    ):
        raise ValueError("invalid_models")
    evidence = Evidence(limits)
    public_policies = []
    models = []
    try:
        headers = decode(data, limits)
        parsed = []
        for index, header in enumerate(headers):
            evidence.charge("headers")
            parsed.extend(parse_header(header["value"], header["disposition"], index, evidence))
        enforced = {2: [], 3: []}
        for policy in parsed:
            public = {k: v for k, v in policy.items() if k != "directives"}
            public["models"] = []
            for version in versions:
                model, internal = model_policy(policy, version, evidence)
                public["models"].append(model)
                if policy["disposition"] == "enforce":
                    enforced[version].append(internal)
            public_policies.append(public)
        for version in versions:
            models.append(combined(enforced[version], version, evidence))
    except Incomplete as exc:
        evidence.open = True
        if len(evidence.findings) < limits.findings:
            evidence.emit(str(exc), "OPEN")
    return evidence.finish(data, public_policies, models)


def review_file(path, *, limits=None, versions=(2, 3)):
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise ValueError("limits_required")
    limits.validate()
    if (
        type(versions) is not tuple
        or not versions
        or any(type(v) is not int or v not in {2, 3} for v in versions)
        or len(set(versions)) != len(versions)
    ):
        raise ValueError("invalid_models")
    try:
        data = read_regular(path, limits.input_bytes)
    except (OSError, ValueError, TypeError, UnicodeError):
        evidence = Evidence(limits)
        evidence.emit("input_unavailable_or_unsafe", "OPEN")
        report = evidence.finish(b"", [], [])
        report["input_sha256"] = None
        report["input_bytes"] = None
        return report
    return review_bytes(data, limits=limits, versions=versions)
