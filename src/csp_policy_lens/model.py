"""CSP2/3 finite effective directives and monotone combined restrictions.

This is a static policy model, not a browser or URL/redirect matching engine.
"""

import re

from .contracts import digest
from .parser import FETCH, kind

V3_ONLY = frozenset(
    {
        "worker-src",
        "manifest-src",
        "script-src-elem",
        "script-src-attr",
        "style-src-elem",
        "style-src-attr",
        "report-to",
        "trusted-types",
        "require-trusted-types-for",
    }
)
TARGETS = (
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "worker-src",
    "frame-src",
    "object-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "connect-src",
    "img-src",
    "font-src",
    "media-src",
    "manifest-src",
)
TT_NAME = re.compile(r"[A-Za-z0-9\-#=_/@.%]+")


def effective(directives, target, version):
    available = {k: v for k, v in directives.items() if version == 3 or k not in V3_ONLY}
    if target in {"script-src-elem", "script-src-attr", "style-src-elem", "style-src-attr"}:
        chain = (
            [target, target.rsplit("-", 1)[0], "default-src"]
            if version == 3
            else [target.rsplit("-", 1)[0], "default-src"]
        )
    elif target == "worker-src":
        chain = (
            ["worker-src", "child-src", "script-src", "default-src"]
            if version == 3
            else ["child-src", "default-src"]
        )
    elif target == "frame-src":
        chain = ["frame-src", "child-src", "default-src"]
    elif target == "manifest-src" and version == 2:
        return None
    elif target in FETCH and target != "default-src":
        chain = [target, "default-src"]
    else:
        chain = [target]
    return next((available[name] for name in chain if name in available), None)


def categories(directive, version):
    return (
        [] if directive is None else [(token, kind(token, version)) for token in directive.values]
    )


def unrestricted_inline(entries, script):
    if entries is None:
        return "ALLOWED"
    kinds = {category for _, category in entries}
    if kinds & {"nonce", "hash"} or (script and "strict-dynamic" in kinds):
        return "BLOCKED"
    if "unsafe-inline" in kinds:
        return "ALLOWED"
    if "unmodeled_keyword" in kinds:
        return "OPEN"
    return "BLOCKED"


def source_class(directive, version):
    if directive is None:
        return "UNRESTRICTED"
    kinds = {category for _, category in categories(directive, version)}
    if "unmodeled_keyword" in kinds:
        return "OPEN"
    url_kinds = kinds & {"wildcard", "host", "scheme", "self"}
    if not url_kinds:
        return "DENY_ALL"
    if url_kinds == {"self"}:
        return "SELF_ONLY"
    if url_kinds == {"wildcard"}:
        return "NETWORK_WILDCARD"
    return "ALLOWLIST"


def tt_configuration(directives, version, evidence, where):
    require = directives.get("require-trusted-types-for") if version == 3 else None
    configured = directives.get("trusted-types") if version == 3 else None
    required = False
    sink_valid = True
    creation_valid = True
    if require:
        for token in require.values:
            if token.text == "'script'":
                required = True
            else:
                sink_valid = False
                evidence.emit(
                    "unmodeled_trusted_types_sink_group", "OPEN", **where, offset=token.offset
                )
    names = set()
    wildcard = configured is None
    duplicates = configured is None
    if configured:
        for token in configured.values:
            if token.text == "*":
                wildcard = True
            elif token.text == "'allow-duplicates'":
                duplicates = True
            elif token.text == "'none'":
                pass
            elif TT_NAME.fullmatch(token.text):
                names.add(token.text)
            else:
                creation_valid = False
                evidence.emit(
                    "invalid_trusted_types_policy_token", "OPEN", **where, offset=token.offset
                )
    return {
        "required": True if required else False if sink_valid else None,
        "wildcard": wildcard,
        "duplicates": duplicates,
        "names": names,
        "sink_valid": sink_valid,
        "creation_valid": creation_valid,
        "configured": configured is not None,
    }


def model_policy(policy, version, evidence):
    directives = policy["directives"]
    where = {"header": policy["header"], "policy": policy["policy"], "model": version}
    selected = {target: effective(directives, target, version) for target in TARGETS}
    table = []
    for target, directive in selected.items():
        entries = categories(directive, version)
        kinds = {category for _, category in entries}
        script = target in {"script-src", "script-src-elem", "script-src-attr"}
        active_dynamic = script and version == 3 and "strict-dynamic" in kinds
        inline_suppressed = bool(kinds & {"nonce", "hash"}) or active_dynamic
        public = []
        for token, category in entries:
            row = token.public(category)
            reasons = []
            if category in {
                "invalid_source",
                "invalid_source_for_model",
                "unsupported_keyword_for_model",
            }:
                reasons.append("ignored_by_selected_model")
            if category == "none" and len(entries) > 1:
                reasons.append("none_not_an_override_for_other_sources")
            if (
                category == "unsafe-inline"
                and inline_suppressed
                and target.startswith(("script-", "style-"))
            ):
                reasons.append("ignored_for_unrestricted_inline")
            if (
                active_dynamic
                and target != "script-src-attr"
                and category in {"host", "scheme", "wildcard", "self", "unsafe-inline"}
            ):
                reasons.append("ignored_for_script_url_matching")
            row["effects"] = reasons
            public.append(row)
        table.append(
            {
                "target": target,
                "source_directive": directive.name if directive else None,
                "source_offset": directive.token.offset if directive else None,
                "tokens": public,
                "raw_url_source_class": source_class(directive, version),
            }
        )
    inline = {}
    for label, target, script in [
        ("script_element_inline", "script-src-elem", True),
        ("script_attribute_inline", "script-src-attr", True),
        ("style_element_inline", "style-src-elem", False),
        ("style_attribute_inline", "style-src-attr", False),
    ]:
        directive = selected[target]
        inline[label] = unrestricted_inline(
            None if directive is None else categories(directive, version), script
        )
    eval_directive = selected["script-src"]
    eval_kinds = {category for _, category in categories(eval_directive, version)}
    inline["string_eval"] = (
        "ALLOWED"
        if eval_directive is None or "unsafe-eval" in eval_kinds
        else "OPEN"
        if "unmodeled_keyword" in eval_kinds
        else "BLOCKED"
    )
    inline["wasm_eval"] = (
        "ALLOWED"
        if eval_directive is None or "unsafe-eval" in eval_kinds or "wasm-unsafe-eval" in eval_kinds
        else "OPEN"
        if "unmodeled_keyword" in eval_kinds
        else "BLOCKED"
    )
    tt = tt_configuration(directives, version, evidence, where)
    elem_kinds = {category for _, category in categories(selected["script-src-elem"], version)}
    strict = (
        version == 3 and bool(elem_kinds & {"nonce", "hash"}) and "strict-dynamic" in elem_kinds
    )
    internal = {
        "inline": inline,
        "object": source_class(selected["object-src"], version),
        "base": source_class(selected["base-uri"], version),
        "tt": tt,
    }
    public = {
        "model": version,
        "effective_directives": table,
        "capabilities": inline,
        "object_source_class": internal["object"],
        "base_source_class": internal["base"],
        "nonce_or_hash_with_strict_dynamic": strict,
        "trusted_types": {
            "script_sink_requirement": tt["required"],
            "creation_wildcard": tt["wildcard"],
            "duplicate_names_allowed_by_csp": tt["duplicates"],
            "policy_name_sha256": sorted(digest(name) for name in tt["names"]),
            "default_policy_name_allowed": tt["wildcard"] or "default" in tt["names"],
        },
    }
    return public, internal


def conjunction(values):
    return "BLOCKED" if "BLOCKED" in values else "OPEN" if "OPEN" in values else "ALLOWED"


def combined(internals, version, evidence):
    capabilities = {
        label: conjunction([item["inline"][label] for item in internals])
        for label in (
            "script_element_inline",
            "script_attribute_inline",
            "style_element_inline",
            "style_attribute_inline",
            "string_eval",
            "wasm_eval",
        )
    }
    objects = [item["object"] for item in internals]
    bases = [item["base"] for item in internals]
    capabilities["object_loading"] = (
        "BLOCKED"
        if "DENY_ALL" in objects
        else "ALLOWED"
        if all(x in {"UNRESTRICTED", "NETWORK_WILDCARD"} for x in objects)
        else "OPEN"
    )
    capabilities["base_outside_self"] = (
        "BLOCKED"
        if any(x in {"DENY_ALL", "SELF_ONLY"} for x in bases)
        else "ALLOWED"
        if all(x in {"UNRESTRICTED", "NETWORK_WILDCARD"} for x in bases)
        else "OPEN"
    )
    # A conservative baseline, separate from style/wasm hardening and TT adoption.
    for label in (
        "script_element_inline",
        "script_attribute_inline",
        "string_eval",
        "object_loading",
        "base_outside_self",
    ):
        state = capabilities[label]
        if state == "ALLOWED":
            evidence.emit("combined_baseline_permissive_" + label, "FAIL", model=version)
        elif state == "OPEN":
            evidence.emit("combined_baseline_unproved_" + label, "OPEN", model=version)
    tt_items = [item["tt"] for item in internals]
    required = any(item["required"] is True for item in tt_items)
    allowed = None
    valid = all(item["creation_valid"] for item in tt_items)
    sinks_valid = all(item["sink_valid"] for item in tt_items)
    if valid:
        for item in tt_items:
            if not item["wildcard"]:
                allowed = set(item["names"]) if allowed is None else allowed & item["names"]
    tt = {
        "script_sink_requirement": True if required else False if sinks_valid else None,
        "creation_name_intersection": "OPEN"
        if not valid
        else "ANY"
        if allowed is None
        else "FINITE",
        "policy_name_sha256": sorted(digest(name) for name in allowed)
        if valid and allowed is not None
        else [],
        "duplicate_names_allowed_by_csp": all(item["duplicates"] for item in tt_items)
        if valid
        else None,
        "default_policy_name_allowed": (allowed is None or "default" in allowed) if valid else None,
    }
    return {
        "model": version,
        "enforced_policies": len(internals),
        "capabilities": capabilities,
        "trusted_types": tt,
        "arbitrary_url_intersection": "OPEN",
    }
