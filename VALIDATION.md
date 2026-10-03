## Current version 0.1.1: attribution and bounded verification, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.1`.

Required local reader/writer protection flags now require positive non-Boolean integers. Missing, zero, None, Boolean, string and floating-point values yield controlled OPEN/error before requested filesystem input/output. Existing fixed-source provenance and parser/generation scope are retained.

The current source suite passes 45 tests on Python 3.14/macOS arm64. Final wheel and sdist are built from the final files. A fresh consumer installation also passes 45 tests. Installed/source/wheel runtime bytes, licenses, retained upstream notices, RECORD and command contracts are verified separately before publication. Exact package hashes and execution receipts are recorded externally rather than embedded in this self-referential document.

These tests verify the documented finite profile. Historical native/reference measurements below are preserved; they are not new runs for this revision. Matching remote CI, actual deployments, applicant identity and CVP approval remain OPEN until separately evidenced.

The current directory-relative file contract also requires `os.supports_dir_fd` to be a set or frozenset containing the actual `os.open`. Missing, None, malformed and incomplete declarations yield the existing controlled OPEN/error before requested filesystem I/O. The same current suite covers these API and real installed CLI contrasts, including normal frozenset capability declarations. Trusted CLI and standard-library imports are warmed before simulated capability mutation; this test isolates the application gate rather than a damaged standard-library import. Source archive offline rebuilding and another fresh consumer verify the same suite and all uncompressed wheel payload bytes.

## Prior verification evidence

# Validation

Local verification on macOS arm64 with Python 3.14.6 covers 42 unittest methods, including an independent 25-pair inline/conjunction oracle for both CSP versions, strict JSON and file budgets, effective fallback/empty overrides, report-only exclusion, Trusted Types name intersection and sink separation, model selection, positions and private errors. An independent reviewer read all nine runtime files and 42 test methods and checked 25 additional cases against the final runtime hashes.

The parent verification uses a fresh offline installed wheel from outside this source tree, six direct console cases, help/version/module entrypoints, and five audit-observed library cases. After the module is imported, library calls are monitored for import, execution, process, socket and write-open events. Input files remain byte-identical. This is observation of these cases, not a general execution sandbox proof.

Wheel RECORD hashes and sizes, all ten runtime/typed files, installed bytes, package metadata and all complete license files are checked. The source distribution is compared with current local source files and rebuilt into a separate fresh environment. GitHub CI runs the source and installed wheel tests on Python 3.11 and 3.14; its actual outcome is recorded externally only after the corresponding commit has run.

The fixtures in `evidence/` are synthetic decoded header envelopes, never browser code. Grammar acceptance, hash text, nonce length and a finite baseline PASS do not establish a matching digest, nonce entropy, actual delivery, browser behavior, Trusted Types API default-policy uniqueness, XSS elimination or CVP eligibility. The CSP3 and Trusted Types references are dated Working Drafts; unsupported/future semantics remain OPEN.
