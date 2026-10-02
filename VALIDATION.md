# Validation

Local verification on macOS arm64 with Python 3.14.6 covers 42 unittest methods, including an independent 25-pair inline/conjunction oracle for both CSP versions, strict JSON and file budgets, effective fallback/empty overrides, report-only exclusion, Trusted Types name intersection and sink separation, model selection, positions and private errors. An independent reviewer read all nine runtime files and 42 test methods and checked 25 additional cases against the final runtime hashes.

The parent verification uses a fresh offline installed wheel from outside this source tree, six direct console cases, help/version/module entrypoints, and five audit-observed library cases. After the module is imported, library calls are monitored for import, execution, process, socket and write-open events. Input files remain byte-identical. This is observation of these cases, not a general execution sandbox proof.

Wheel RECORD hashes and sizes, all ten runtime/typed files, installed bytes, package metadata and all complete license files are checked. The source distribution is compared with current local source files and rebuilt into a separate fresh environment. GitHub CI runs the source and installed wheel tests on Python 3.11 and 3.14; its actual outcome is recorded externally only after the corresponding commit has run.

The fixtures in `evidence/` are synthetic decoded header envelopes, never browser code. Grammar acceptance, hash text, nonce length and a finite baseline PASS do not establish a matching digest, nonce entropy, actual delivery, browser behavior, Trusted Types API default-policy uniqueness, XSS elimination or CVP eligibility. The CSP3 and Trusted Types references are dated Working Drafts; unsupported/future semantics remain OPEN.
