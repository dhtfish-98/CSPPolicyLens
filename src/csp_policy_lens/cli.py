"""One local envelope in, compact private JSON out."""

import argparse
import json

from .review import review_file


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("arguments")


def main(argv=None):
    parser = Parser(description="Offline CSP2/3 policy model; no browser or fetch")
    parser.add_argument("path")
    parser.add_argument("--model", choices=("2", "3", "both"), default="both")
    parser.add_argument("--version", action="version", version="CSPPolicyLens 0.1.3")
    try:
        args = parser.parse_args(argv)
        report = review_file(
            args.path, versions=(2, 3) if args.model == "both" else (int(args.model),)
        )
    except (ValueError, TypeError, OSError, UnicodeError):
        report = {
            "schema_version": 1,
            "status": "OPEN",
            "analysis_completeness": "INCOMPLETE",
            "findings": [{"code": "arguments_or_input_error", "status": "OPEN"}],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
