"""Strict finite JSON envelope. No source fragments appear in errors."""

import json

from .contracts import Incomplete


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Incomplete("duplicate_json_key")
        result[key] = value
    return result


def decode(data, limits):
    if len(data) > limits.input_bytes:
        raise Incomplete("budget_input_bytes")
    try:
        root = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Incomplete("nonfinite_json")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, Incomplete):
            raise
        raise Incomplete("invalid_json") from exc
    nodes = 0
    stack = [(root, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > limits.json_nodes or depth > limits.json_depth:
            raise Incomplete("budget_json_tree")
        if type(value) is dict:
            stack.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            stack.extend((child, depth + 1) for child in value)
    if type(root) is not dict or set(root) != {"schema_version", "headers"}:
        raise Incomplete("envelope_schema")
    if (
        type(root["schema_version"]) is not int
        or root["schema_version"] != 1
        or type(root["headers"]) is not list
    ):
        raise Incomplete("envelope_schema")
    headers = root["headers"]
    if len(headers) > limits.headers:
        raise Incomplete("budget_headers")
    for header in headers:
        if type(header) is not dict or set(header) != {"disposition", "value"}:
            raise Incomplete("header_schema")
        if (
            type(header["disposition"]) is not str
            or header["disposition"] not in {"enforce", "report-only"}
            or type(header["value"]) is not str
        ):
            raise Incomplete("header_schema")
    return headers
