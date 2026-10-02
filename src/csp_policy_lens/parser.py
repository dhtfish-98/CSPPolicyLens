"""Positioned CSP header-list parser, first duplicate directive wins."""

import re
from dataclasses import dataclass

from .contracts import Incomplete, digest

SPACE = " \t\n\r\f"
FETCH = frozenset(
    {
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "font-src",
        "media-src",
        "object-src",
        "connect-src",
        "child-src",
        "frame-src",
        "worker-src",
        "manifest-src",
        "script-src-elem",
        "script-src-attr",
        "style-src-elem",
        "style-src-attr",
    }
)
SOURCE = FETCH | {"base-uri", "form-action", "frame-ancestors"}
KNOWN = SOURCE | {
    "report-uri",
    "report-to",
    "sandbox",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "trusted-types",
    "require-trusted-types-for",
}
KEYWORDS = frozenset(
    {
        "none",
        "self",
        "unsafe-inline",
        "unsafe-eval",
        "strict-dynamic",
        "unsafe-hashes",
        "report-sample",
        "wasm-unsafe-eval",
    }
)
FUTURE_KEYWORDS = frozenset(
    {
        "trusted-types-eval",
        "unsafe-allow-redirects",
        "report-sha256",
        "report-sha384",
        "report-sha512",
        "unsafe-webtransport-hashes",
        "inline-speculation-rules",
    }
)
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
HOST = re.compile(
    r"(?:(?:[A-Za-z][A-Za-z0-9+.-]*)://)?(?:\*|(?:\*\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.?)(?::(?:[0-9]+|\*))?(?:/[A-Za-z0-9._~!$&'()*+%=:@/\-]*)?"
)
NONCE = re.compile(r"'nonce-([A-Za-z0-9+/_-]+={0,2})'", re.I)
HASH = re.compile(r"'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'", re.I)


@dataclass(frozen=True)
class Token:
    text: str
    offset: int
    end: int
    line: int
    column: int

    def public(self, kind):
        return {
            "kind": kind,
            "sha256": digest(self.text),
            "offset": self.offset,
            "end": self.end,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class Directive:
    name: str
    token: Token
    values: list


def token_at(text, start, end):
    return Token(
        text[start:end],
        start,
        end,
        text.count("\n", 0, start) + 1,
        start - text.rfind("\n", 0, start),
    )


def kind(token, version):
    text = token.text
    folded = text.lower()
    if folded.startswith("'") and folded.endswith("'"):
        inner = folded[1:-1]
        if inner in KEYWORDS:
            if version == 2 and inner in {
                "strict-dynamic",
                "unsafe-hashes",
                "report-sample",
                "wasm-unsafe-eval",
            }:
                return "unsupported_keyword_for_model"
            return inner
        if inner in FUTURE_KEYWORDS:
            return "unmodeled_keyword"
    nonce = NONCE.fullmatch(text)
    hashed = HASH.fullmatch(text)
    if nonce or hashed:
        value = nonce[1] if nonce else hashed[2]
        if version == 2 and any(c in value for c in "-_"):
            return "invalid_source_for_model"
        return "nonce" if nonce else "hash"
    if text == "*":
        return "wildcard"
    if SCHEME.fullmatch(text):
        return "scheme"
    if HOST.fullmatch(text):
        return "host"
    return "invalid_source"


def parse_header(text, disposition, header, evidence):
    if len(text.encode("utf-8", "surrogatepass")) > evidence.limits.policy_bytes:
        raise Incomplete("budget_policy_bytes")
    policies = []
    base = 0
    # CSP headers use a comma-separated list, not a quoted CSV language.
    for part in text.split(","):
        evidence.charge("policies")
        index = evidence.counts["policies"] - 1
        where = {"header": header, "policy": index}
        directives = {}
        rows = []
        offset = base
        for section in part.split(";"):
            pieces = list(re.finditer(r"[^ \t\n\r\f]+", section))
            if pieces:
                evidence.charge("directives")
                first = pieces[0]
                name_token = token_at(text, offset + first.start(), offset + first.end())
                if (
                    len(name_token.text.encode("utf-8", "surrogatepass"))
                    > evidence.limits.token_bytes
                ):
                    raise Incomplete("budget_token_bytes")
                name = name_token.text.lower()
                values = []
                for piece in pieces[1:]:
                    evidence.charge("tokens")
                    token = token_at(text, offset + piece.start(), offset + piece.end())
                    if (
                        len(token.text.encode("utf-8", "surrogatepass"))
                        > evidence.limits.token_bytes
                    ):
                        raise Incomplete("budget_token_bytes")
                    values.append(token)
                row = {
                    "name": name if name in KNOWN else "unknown",
                    "name_sha256": digest(name_token.text),
                    "position": name_token.public("directive"),
                    "value_count": len(values),
                    "first_wins": name not in directives,
                }
                rows.append(row)
                if name in directives:
                    evidence.emit("duplicate_directive_ignored", **where, offset=name_token.offset)
                elif not section.isascii() or any(
                    ord(c) < 32 and c not in SPACE or ord(c) == 127 for c in section
                ):
                    evidence.emit(
                        "nonascii_or_control_directive_unmodeled",
                        "OPEN",
                        **where,
                        offset=name_token.offset,
                    )
                else:
                    directives[name] = Directive(name, name_token, values)
                    if name not in KNOWN:
                        evidence.emit(
                            "unknown_directive_ignored_by_selected_models",
                            "OPEN",
                            **where,
                            offset=name_token.offset,
                        )
                    for token in values:
                        if token.text.lower() in KNOWN:
                            evidence.emit(
                                "possible_missing_semicolon", "OPEN", **where, offset=token.offset
                            )
                    if name == "sandbox":
                        evidence.emit(
                            "sandbox_runtime_effect_unmodeled",
                            "OPEN",
                            **where,
                            offset=name_token.offset,
                        )
                    if name in SOURCE:
                        for token in values:
                            bare = token.text.lower()
                            if bare in KEYWORDS or bare.startswith(
                                ("nonce-", "sha256-", "sha384-", "sha512-")
                            ):
                                evidence.emit(
                                    "possible_missing_source_quotes",
                                    "OPEN",
                                    **where,
                                    offset=token.offset,
                                )
                            category = kind(token, 3)
                            if category in {"invalid_source", "unmodeled_keyword"}:
                                evidence.emit(
                                    category,
                                    "OPEN",
                                    **where,
                                    offset=token.offset,
                                    token_sha256=digest(token.text),
                                )
                            nonce = NONCE.fullmatch(token.text)
                            if nonce and len(nonce[1].rstrip("=")) * 6 < 128:
                                evidence.emit(
                                    "nonce_length_below_128bit_recommendation",
                                    "WARN",
                                    **where,
                                    offset=token.offset,
                                )
            offset += len(section) + 1
        if not directives:
            evidence.emit("empty_policy_has_no_selected_restrictions", **where, offset=base)
        policies.append(
            {
                "header": header,
                "policy": index,
                "disposition": disposition,
                "start": base,
                "end": base + len(part),
                "directives": directives,
                "directive_rows": rows,
                "policy_sha256": digest(part),
            }
        )
        base += len(part) + 1
    return policies
