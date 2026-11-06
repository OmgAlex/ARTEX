"""python3 -m whitehat demo DIRECTORY | report MANIFEST --out DIRECTORY"""
import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .advisory import Provider, advise
from .common import Invalid, require
from .demo import demo
from .metrics import benchmark
from .render import to_html
from .verify import evaluate


def write_report(report, destination):
    # Publish a complete pair at a fresh path; a retry cannot mix two reports.
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists(), "output directory already exists; choose a new directory")
    with tempfile.TemporaryDirectory(dir=destination.parent) as staging:
        bundle = Path(staging) / "report"
        bundle.mkdir(mode=0o700)
        (bundle/"report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        (bundle/"report.html").write_text(to_html(report), encoding="utf-8")
        os.rename(bundle, destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description="ARTEX offline evidence verification")
    commands = parser.add_subparsers(dest="command", required=True)
    sample = commands.add_parser("demo", help="write a synthetic offline case into a new directory")
    sample.add_argument("directory")
    check = commands.add_parser("report", help="evaluate a trusted case manifest against archived observations")
    check.add_argument("manifest")
    check.add_argument("--out", required=True, help="new output directory")
    check.add_argument("--labels", help="independent reference labels for this benchmark only")
    check.add_argument("--models", action="store_true", help="enable optional redacted GLM/Qwen review")
    check.add_argument("--max-calls", type=int, default=12)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            print(demo(args.directory))
            return 0
        require(1 <= args.max_calls <= 128, "max-calls must be between 1 and 128")
        report = evaluate(args.manifest)
        if args.labels:
            benchmark(report, args.labels)
        if args.models:
            try:
                strong, worker = Provider("strong"), Provider("worker")
            except ValueError:
                report["model_review"] = {"budget": args.max_calls, "calls": 0, "processed": 0,
                                          "status": "provider_configuration_error"}
            else:
                advise(report, strong, worker, args.max_calls)
        write_report(report, args.out)
        print(str(Path(args.out) / "report.html"))
        if report["counts"]["invalid_evidence"]:
            return 2
        if args.models and report["model_review"]["status"] != "completed":
            return 3
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("whitehat: " + (str(exc) if isinstance(exc, Invalid) else "invalid input or filesystem error"),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
