import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from csp_policy_lens import Limits, review_bytes, review_file
from csp_policy_lens.cli import main
from csp_policy_lens.parser import kind, token_at


def envelope(*values, disposition="enforce"):
    return json.dumps(
        {
            "schema_version": 1,
            "headers": [{"disposition": disposition, "value": value} for value in values],
        }
    ).encode()


def model(report, version=3):
    return next(x for x in report["combined_enforced_models"] if x["model"] == version)


def capability(report, label, version=3):
    return model(report, version)["capabilities"][label]


def table(report, target, version=3, policy=0):
    model = next(x for x in report["policies"][policy]["models"] if x["model"] == version)
    return next(x for x in model["effective_directives"] if x["target"] == target)


STRICT = "default-src 'none'; script-src 'nonce-AAAAAAAAAAAAAAAAAAAAAA' 'strict-dynamic'; base-uri 'none'"


class ReviewTests(unittest.TestCase):
    def test_finite_deny_all_pass(self):
        report = review_bytes(envelope("default-src 'none'; base-uri 'none'"))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["external"]["xss_elimination"], "OPEN")

    def test_nonce_dynamic_profile(self):
        report = review_bytes(envelope(STRICT))
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["policies"][0]["models"][1]["nonce_or_hash_with_strict_dynamic"])
        self.assertFalse(report["policies"][0]["models"][0]["nonce_or_hash_with_strict_dynamic"])

    def test_first_duplicate_case_insensitive_wins(self):
        report = review_bytes(
            envelope("DEFAULT-SRC 'NoNe'; default-src *; BASE-URI 'SELF'; base-uri *")
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(table(report, "script-src")["tokens"][0]["kind"], "none")
        self.assertEqual(
            [x["first_wins"] for x in report["policies"][0]["directive_rows"]],
            [True, False, True, False],
        )

    def test_reverse_duplicate_permissive_remains(self):
        report = review_bytes(envelope("default-src *; DEFAULT-SRC 'none'; base-uri 'none'"))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(capability(report, "object_loading"), "ALLOWED")

    def test_empty_policy_and_empty_envelope_fail(self):
        for data in [envelope(""), envelope(" ; ; "), envelope()]:
            with self.subTest(data=data):
                self.assertEqual(review_bytes(data)["status"], "FAIL")

    def test_unknown_and_invalid_tokens_open(self):
        for extra in [
            "; mystery-src 'none'",
            "; script-src 'unknown'",
            "; script-src 'nonce-a$'",
            "; script-src 'sha256-a$'",
        ]:
            report = review_bytes(envelope("default-src 'none'; base-uri 'none'" + extra))
            self.assertEqual(report["status"], "OPEN")

    def test_missing_semicolon_retains_known_failure(self):
        report = review_bytes(envelope("script-src 'none' object-src 'none'; base-uri 'none'"))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["analysis_completeness"], "INCOMPLETE")
        self.assertIn("possible_missing_semicolon", [x["code"] for x in report["findings"]])

    def test_bare_keywords_are_hosts_not_keywords(self):
        report = review_bytes(
            envelope("default-src 'none'; script-src unsafe-inline nonce-abc; base-uri 'none'")
        )
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(
            [x["kind"] for x in table(report, "script-src")["tokens"]], ["host", "host"]
        )
        self.assertEqual(capability(report, "script_element_inline"), "BLOCKED")

    def test_effective_source_fallback_and_override(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src 'self'; script-src-elem 'unsafe-inline'; script-src-attr 'none'; base-uri 'none'"
            )
        )
        self.assertEqual(capability(report, "script_element_inline", 2), "BLOCKED")
        self.assertEqual(capability(report, "script_element_inline", 3), "ALLOWED")
        self.assertEqual(capability(report, "script_attribute_inline", 3), "BLOCKED")
        self.assertEqual(table(report, "script-src-elem", 2)["source_directive"], "script-src")

    def test_empty_override_blocks_fallback(self):
        report = review_bytes(
            envelope(
                "default-src 'unsafe-inline' 'unsafe-eval' *; script-src; object-src; base-uri"
            )
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(table(report, "script-src-elem")["source_directive"], "script-src")

    def test_script_nonce_does_not_override_element_directive(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src 'nonce-abc'; script-src-elem 'unsafe-inline'; base-uri 'none'"
            )
        )
        self.assertEqual(capability(report, "script_element_inline"), "ALLOWED")
        self.assertEqual(capability(report, "script_element_inline", 2), "BLOCKED")

    def test_unsafe_inline_nonce_hash_suppression(self):
        for token in ["'nonce-aBcD'", "'sha256-AAAA'", "'sha384-AAAA'", "'sha512-AAAA'"]:
            report = review_bytes(
                envelope(
                    "default-src 'none'; script-src 'unsafe-inline' " + token + "; base-uri 'none'"
                )
            )
            for version in (2, 3):
                self.assertEqual(capability(report, "script_element_inline", version), "BLOCKED")
                self.assertEqual(capability(report, "script_attribute_inline", version), "BLOCKED")
                effects = table(report, "script-src", version)["tokens"][0]["effects"]
                self.assertIn("ignored_for_unrestricted_inline", effects)

    def test_base64url_is_version_specific(self):
        report = review_bytes(
            envelope("default-src 'none'; script-src 'unsafe-inline' 'nonce-A_B-'; base-uri 'none'")
        )
        self.assertEqual(capability(report, "script_element_inline", 2), "ALLOWED")
        self.assertEqual(capability(report, "script_element_inline", 3), "BLOCKED")

    def test_dynamic_without_nonce_suppresses_inline_in_csp3(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src 'unsafe-inline' 'strict-dynamic'; base-uri 'none'"
            )
        )
        self.assertEqual(capability(report, "script_element_inline", 2), "ALLOWED")
        self.assertEqual(capability(report, "script_element_inline", 3), "BLOCKED")
        self.assertFalse(report["policies"][0]["models"][1]["nonce_or_hash_with_strict_dynamic"])

    def test_dynamic_ignores_host_for_script_only(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src 'strict-dynamic' 'nonce-abc' https: 'self' * example.invalid; style-src 'strict-dynamic' 'unsafe-inline'; base-uri 'none'"
            )
        )
        for row in table(report, "script-src")["tokens"][2:]:
            self.assertIn("ignored_for_script_url_matching", row["effects"])
        for row in table(report, "script-src", 2)["tokens"][2:]:
            self.assertNotIn("ignored_for_script_url_matching", row["effects"])
        self.assertEqual(capability(report, "style_element_inline"), "ALLOWED")

    def test_eval_is_script_src_not_element_src(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src 'unsafe-eval'; script-src-elem 'none'; script-src-attr 'none'; base-uri 'none'"
            )
        )
        self.assertEqual(capability(report, "string_eval"), "ALLOWED")
        opposite = review_bytes(
            envelope("default-src 'none'; script-src-elem 'unsafe-eval'; base-uri 'none'")
        )
        self.assertEqual(capability(opposite, "string_eval"), "BLOCKED")

    def test_wasm_keyword_version_is_separate(self):
        report = review_bytes(
            envelope("default-src 'none'; script-src 'wasm-unsafe-eval'; base-uri 'none'")
        )
        self.assertEqual(capability(report, "string_eval"), "BLOCKED")
        self.assertEqual(capability(report, "wasm_eval"), "ALLOWED")
        self.assertEqual(capability(report, "wasm_eval", 2), "BLOCKED")

    def test_worker_and_frame_fallback_order(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; script-src script.invalid; child-src child.invalid; worker-src worker.invalid; frame-src frame.invalid; base-uri 'none'"
            )
        )
        self.assertEqual(table(report, "worker-src")["source_directive"], "worker-src")
        self.assertEqual(table(report, "worker-src", 2)["source_directive"], "child-src")
        self.assertEqual(table(report, "frame-src")["source_directive"], "frame-src")
        second = review_bytes(
            envelope("default-src 'none'; script-src script.invalid; base-uri 'none'")
        )
        self.assertEqual(table(second, "worker-src")["source_directive"], "script-src")
        self.assertEqual(table(second, "worker-src", 2)["source_directive"], "default-src")

    def test_nonfetch_never_default_fallback(self):
        report = review_bytes(envelope("default-src 'none'"))
        for target in ["base-uri", "form-action", "frame-ancestors"]:
            self.assertIsNone(table(report, target)["source_directive"])
        self.assertEqual(report["status"], "FAIL")

    def test_none_mixed_not_override(self):
        report = review_bytes(envelope("default-src 'none'; object-src 'none' *; base-uri 'none'"))
        self.assertEqual(capability(report, "object_loading"), "ALLOWED")
        self.assertIn(
            "none_not_an_override_for_other_sources",
            table(report, "object-src")["tokens"][0]["effects"],
        )

    def test_host_intersection_not_falsely_proven(self):
        report = review_bytes(
            envelope(
                "default-src 'none'; object-src a.invalid; base-uri 'none'",
                "default-src 'none'; object-src b.invalid; base-uri 'none'",
            )
        )
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(capability(report, "object_loading"), "OPEN")

    def test_multi_policy_conjunction(self):
        report = review_bytes(
            envelope(
                "default-src 'unsafe-inline' 'unsafe-eval' *; base-uri *",
                "default-src 'none'; base-uri 'none'",
            )
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(model(report)["enforced_policies"], 2)
        for state in model(report)["capabilities"].values():
            self.assertEqual(state, "BLOCKED")

    def test_comma_policies_have_independent_positions(self):
        value = "script-src 'unsafe-inline', default-src 'none'; base-uri 'none'"
        report = review_bytes(envelope(value))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["policies"]), 2)
        self.assertEqual(report["policies"][1]["start"], value.index(",") + 1)
        self.assertEqual(
            table(report, "script-src", policy=1)["source_offset"], value.index("default-src")
        )

    def test_report_only_never_enforces(self):
        report = review_bytes(
            envelope("default-src 'none'; base-uri 'none'", disposition="report-only")
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(model(report)["enforced_policies"], 0)
        data = {
            "schema_version": 1,
            "headers": [
                {"disposition": "enforce", "value": "default-src *; base-uri *"},
                {"disposition": "report-only", "value": "default-src 'none'; base-uri 'none'"},
            ],
        }
        self.assertEqual(
            capability(review_bytes(json.dumps(data).encode()), "object_loading"), "ALLOWED"
        )

    def test_finite_nonce_quality_is_not_entropy(self):
        report = review_bytes(envelope(STRICT.replace("AAAAAAAAAAAAAAAAAAAAAA", "abc")))
        self.assertEqual(report["status"], "PASS")
        self.assertIn(
            "nonce_length_below_128bit_recommendation", [x["code"] for x in report["findings"]]
        )
        self.assertEqual(report["external"]["nonce_entropy_and_reuse"], "OPEN")

    def test_trusted_types_creation_is_separate_from_sinks(self):
        report = review_bytes(envelope(STRICT + "; trusted-types Alpha Beta"))
        tt = model(report)["trusted_types"]
        self.assertFalse(tt["script_sink_requirement"])
        self.assertEqual(tt["creation_name_intersection"], "FINITE")
        self.assertEqual(len(tt["policy_name_sha256"]), 2)
        self.assertFalse(tt["default_policy_name_allowed"])

    def test_trusted_types_intersection_and_required_or(self):
        report = review_bytes(
            envelope(
                STRICT
                + "; require-trusted-types-for 'script'; trusted-types Alpha Beta 'allow-duplicates'",
                STRICT + "; trusted-types Beta Gamma",
            )
        )
        tt = model(report)["trusted_types"]
        self.assertTrue(tt["script_sink_requirement"])
        self.assertEqual(len(tt["policy_name_sha256"]), 1)
        self.assertFalse(tt["duplicate_names_allowed_by_csp"])
        self.assertFalse(model(report, 2)["trusted_types"]["script_sink_requirement"])

    def test_tt_empty_none_wildcard_default(self):
        for ending in ["trusted-types", "trusted-types 'none'", "trusted-types 'allow-duplicates'"]:
            report = review_bytes(envelope(STRICT + "; " + ending))
            tt = model(report)["trusted_types"]
            self.assertEqual(tt["policy_name_sha256"], [])
            self.assertFalse(tt["default_policy_name_allowed"])
        report = review_bytes(envelope(STRICT + "; trusted-types default 'none'"))
        self.assertTrue(model(report)["trusted_types"]["default_policy_name_allowed"])
        report = review_bytes(envelope(STRICT + "; trusted-types * 'allow-duplicates'"))
        self.assertEqual(model(report)["trusted_types"]["creation_name_intersection"], "ANY")
        self.assertTrue(model(report)["trusted_types"]["duplicate_names_allowed_by_csp"])

    def test_tt_invalid_sink_or_name_open(self):
        for ending in [
            "require-trusted-types-for 'unknown'",
            "trusted-types 'bad'",
            "trusted-types :bad",
            "trusted-types 'NONE'",
            "require-trusted-types-for 'SCRIPT'",
        ]:
            report = review_bytes(envelope(STRICT + "; " + ending))
            self.assertEqual(report["status"], "OPEN")

    def test_tt_reportonly_excluded(self):
        data = {
            "schema_version": 1,
            "headers": [
                {"disposition": "enforce", "value": STRICT},
                {
                    "disposition": "report-only",
                    "value": "require-trusted-types-for 'script'; trusted-types 'none'",
                },
            ],
        }
        tt = model(review_bytes(json.dumps(data).encode()))["trusted_types"]
        self.assertFalse(tt["script_sink_requirement"])
        self.assertEqual(tt["creation_name_intersection"], "ANY")

    def test_tt_independent_directives_retain_known_evidence(self):
        report = review_bytes(
            envelope(STRICT + "; require-trusted-types-for 'script'; trusted-types 'bad'")
        )
        self.assertTrue(model(report)["trusted_types"]["script_sink_requirement"])
        self.assertEqual(model(report)["trusted_types"]["creation_name_intersection"], "OPEN")
        report = review_bytes(
            envelope(STRICT + "; require-trusted-types-for 'unknown'; trusted-types Alpha")
        )
        self.assertIsNone(model(report)["trusted_types"]["script_sink_requirement"])
        self.assertEqual(model(report)["trusted_types"]["creation_name_intersection"], "FINITE")
        self.assertEqual(len(model(report)["trusted_types"]["policy_name_sha256"]), 1)

    def test_private_report_positions(self):
        value = "\n  default-src 'none';\n script-src 'nonce-SECRETNONCEMARKER' https://secret-address.invalid/private-path;\n base-uri 'none'; trusted-types SecretPolicyName"
        report = review_bytes(envelope(value))
        encoded = json.dumps(report)
        for private in [
            "SECRETNONCEMARKER",
            "secret-address.invalid",
            "private-path",
            "SecretPolicyName",
        ]:
            self.assertNotIn(private, encoded)
        token = table(report, "script-src")["tokens"][0]
        self.assertEqual(token["offset"], value.index("'nonce-"))
        self.assertEqual(token["line"], 3)
        self.assertEqual(token["column"], 13)

    def test_nonascii_control_sandbox_future_open(self):
        for value in [
            "default-src 'none'; base-uri 'none'; img-src café.invalid",
            "default-src 'none'; base-uri 'none'; img-src \0",
            "default-src 'none'; base-uri 'none'; sandbox",
            STRICT + " 'trusted-types-eval'",
        ]:
            report = review_bytes(envelope(value))
            self.assertIn(report["status"], {"OPEN", "FAIL"})
            self.assertEqual(report["analysis_completeness"], "INCOMPLETE")

    def test_json_schema_and_duplicates(self):
        for data in [
            b"{}",
            b"[]",
            b'{"schema_version":1,"schema_version":1,"headers":[]}',
            b'{"schema_version":true,"headers":[]}',
            b'{"schema_version":1,"headers":[],"extra":1}',
            b'{"schema_version":1,"headers":[{"disposition":"meta","value":""}]}',
            b'{"schema_version":1,"headers":NaN}',
            b"\xff",
            b"\xef\xbb\xbf{}",
            b"{",
        ]:
            self.assertEqual(review_bytes(data)["status"], "OPEN")

    def test_all_limits_validate(self):
        for invalid in [
            Limits(tokens=0),
            Limits(tokens=True),
            Limits(report_bytes=1),
            Limits(headers=33),
        ]:
            with self.assertRaises(ValueError):
                review_bytes(envelope(STRICT), limits=invalid)
        for data, limit in [
            (envelope(STRICT), Limits(input_bytes=1)),
            (envelope(STRICT), Limits(policy_bytes=1)),
            (envelope(STRICT), Limits(token_bytes=1)),
            (envelope(STRICT), Limits(tokens=1)),
            (envelope(STRICT), Limits(directives=1)),
            (envelope(STRICT, STRICT), Limits(policies=1)),
            (envelope(STRICT, STRICT), Limits(headers=1)),
            (envelope(STRICT), Limits(json_depth=1)),
            (envelope(STRICT), Limits(json_nodes=1)),
        ]:
            self.assertEqual(review_bytes(data, limits=limit)["status"], "OPEN")

    def test_report_budget_and_fail_count_retained(self):
        data = envelope("script-src 'unsafe-inline'; base-uri *")
        report = review_bytes(data, limits=Limits(report_bytes=2048))
        self.assertEqual(report["status"], "FAIL")
        self.assertGreater(report["known_violation_count"], 0)
        self.assertEqual(report["policies"], [])
        self.assertLessEqual(len(json.dumps(report, separators=(",", ":")).encode()), 2048)
        report = review_bytes(envelope(""), limits=Limits(findings=2))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["analysis_completeness"], "INCOMPLETE")

    def test_byte_api_type(self):
        for wrong in ["text", bytearray(), None]:
            with self.assertRaises(ValueError):
                review_bytes(wrong)

    def test_explicit_models_and_validation(self):
        data = envelope(
            "default-src 'none'; script-src 'unsafe-inline' 'nonce-A_B-'; base-uri 'none'"
        )
        self.assertEqual(review_bytes(data, versions=(3,))["status"], "PASS")
        self.assertEqual(review_bytes(data, versions=(2,))["status"], "FAIL")
        for versions in [[], (), (True,), (1,), (2, 2), (3, 4)]:
            with self.assertRaises(ValueError):
                review_bytes(data, versions=versions)

    def test_regular_reader_and_symlink_components(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            target = root / "policy.json"
            target.write_bytes(envelope(STRICT))
            before = target.read_bytes()
            self.assertEqual(review_file(target)["status"], "PASS")
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(review_file(root)["status"], "OPEN")
            (root / "link").symlink_to(target)
            self.assertEqual(review_file(root / "link")["status"], "OPEN")
            (root / "dirlink").symlink_to(root, target_is_directory=True)
            self.assertEqual(review_file(root / "dirlink" / "policy.json")["status"], "OPEN")
            os.mkfifo(root / "fifo")
            self.assertEqual(review_file(root / "fifo")["status"], "OPEN")
            self.assertEqual(review_file(root / ".." / root.name / "policy.json")["status"], "OPEN")

    def test_cli_private_errors_and_valid_json(self):
        for args in [[], ["PRIVATEPATHMARKER"], ["--unknown-private-arg"], ["a", "b"]]:
            out, err = StringIO(), StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(args), 2)
            self.assertEqual(json.loads(out.getvalue())["status"], "OPEN")
            self.assertNotIn("PRIVATE", out.getvalue())
            self.assertEqual(err.getvalue(), "")

    def test_keyword_classifier_matrix(self):
        for text, expected2, expected3 in [
            ("'SELF'", "self", "self"),
            ("'STRICT-DYNAMIC'", "unsupported_keyword_for_model", "strict-dynamic"),
            ("'nonce-aBcD'", "nonce", "nonce"),
            ("'nonce-A_B-'", "invalid_source_for_model", "nonce"),
            ("'sha256-AAAA'", "hash", "hash"),
            ("'nonce-$'", "invalid_source", "invalid_source"),
            ("https:", "scheme", "scheme"),
            ("https://*.example.invalid:443/path", "host", "host"),
            ("*", "wildcard", "wildcard"),
        ]:
            token = token_at(text, 0, len(text))
            self.assertEqual(kind(token, 2), expected2)
            self.assertEqual(kind(token, 3), expected3)

    def test_inline_boolean_or_and_independent_matrix(self):
        # An independent finite oracle for known inline grammar and conjunction.
        import itertools

        choices = [
            "",
            "'unsafe-inline'",
            "'nonce-AAAAAAAAAAAAAAAAAAAAAA'",
            "'sha256-AAAA'",
            "'strict-dynamic'",
        ]
        for left, right in itertools.product(choices, repeat=2):
            policies = [
                "default-src 'none'; script-src " + value + "; base-uri 'none'"
                for value in (left, right)
            ]
            report = review_bytes(envelope(*policies))
            for version in (2, 3):
                allows = [
                    "unsafe-inline" in value
                    and "nonce-" not in value
                    and "sha256-" not in value
                    and not (version == 3 and "strict-dynamic" in value)
                    for value in (left, right)
                ]
                expected = "ALLOWED" if all(allows) else "BLOCKED"
                self.assertEqual(capability(report, "script_element_inline", version), expected)


if __name__ == "__main__":
    unittest.main()
