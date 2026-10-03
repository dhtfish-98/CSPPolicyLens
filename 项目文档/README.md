> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# CSPPolicyLens

Independent offline CSP policy parsing, effective-directive selection and combined enforcement evidence. New implementation author and maintainer: dhtfish98. The new runtime is Python code based on a reviewed fixed Google CSP Evaluator source and primary specifications. It contains no upstream bypass-address database.

Install the reviewed wheel, then run `csp-policy-lens local-policy.json --model both`. The input is an explicit local UTF-8 JSON snapshot:

```json
{"schema_version":1,"headers":[{"disposition":"enforce","value":"default-src 'none'; base-uri 'none'"}]}
```

Each header has disposition `enforce` or `report-only` and a decoded policy value. Commas split policies; semicolons split directives; first duplicate directive wins. Report-only policies are analyzed separately and do not constrain the combined enforcement result. `--model 2` and `--model 3` select a finite CSP model; default `both` checks both and retains either model's known baseline failure.

The baseline checks unrestricted script elements, unrestricted event attributes, string evaluation, object loading and base URLs outside the current origin. Multiple enforced policies combine by conjunction. A proven restriction in one policy remains a restriction after adding policies. Arbitrary host/URL intersections remain OPEN; disjoint allowlists are not treated as a proven empty intersection. Style and WebAssembly flags and Trusted Types configuration are reported separately from the baseline.

Exit codes: 0 PASS, 1 FAIL, 2 OPEN. PASS means the selected finite baseline checks passed in the supplied snapshot. FAIL identifies a known permissive baseline capability. OPEN preserves unsupported, incomplete or unproved analysis, including size and reporting budgets. Known violations outrank uncertainty and their count survives compact reporting.

The report contains token kinds, SHA-256 digests and positions. It excludes raw hosts, paths, nonces, hash payloads and Trusted Types policy names. Offsets are zero-based character positions in each decoded header value; end is exclusive, line and column are one-based with LF line breaks. These are not offsets in the JSON encoding or actual HTTP bytes.

The library offers `review_bytes(data, versions=(2,3), limits=Limits())` and `review_file(path, ...)`. File mode reads one unchanged regular snapshot, rejects every symlink component, directories, FIFOs and parent traversal, and writes nothing. On macOS use physical paths below `/private` when `/tmp` or `/var` are symlink aliases. Byte mode performs no file access. The tool never fetches a page, checks a server, opens a browser, executes a script, posts reports or applies a policy.

Source, model boundaries and validation are recorded in [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>), [SOURCE_REVIEW.json](<../SOURCE_REVIEW.json>) and [VALIDATION.md](<VALIDATION.md>). Actual delivered headers, nonce entropy/reuse, DOM and policy code, browser compatibility, URL/redirect matching, XSS elimination and CVP eligibility remain OPEN. This repository is a new defensive implementation, not evidence of prior applicant contributions or an approval guarantee.

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.
