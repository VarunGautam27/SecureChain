"""SecureChain command-line interface.

  securechain scan <manifest-path>
  securechain check <report.json> --max-severity safe --ignore-file .riskignore.json
  securechain accept <package>@<version> --reason "<text>" --ignore-file .riskignore.json
  securechain gui

Intended to run inside CI/CD (see .github/workflows/dependency-risk-scan.yml):
scan always writes result/report.json and result/report.html, then check reads
that JSON report and exits non-zero if anything above --max-severity (default
safe, i.e. Low/Medium/High/Critical all block) isn't covered by
.riskignore.json. A risk is a risk regardless of tier, nothing short of a
genuinely clean dependency passes without either a real fix or a deliberate,
recorded acceptance.

The optional gui command starts a local preview server (see
securechain/gui/). It is a convenience layer only, never a second
enforcement point: the CI run triggered by a push remains the only result
that actually blocks a merge. Review the report (in the browser through gui,
or as the plain report.html file), fix package.json (upgrade the dependency)
or run accept (record a deliberate exception), then push again.
"""

from __future__ import annotations

import argparse
import getpass
import pathlib
import sys

from securechain.gate import evaluate_gate
from securechain.manifest import ManifestError
from securechain.pipeline import run_scan
from securechain.report_html import render_html_report
from securechain.report_json import load_report, write_report
from securechain.riskignore import accept_risk


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        report = run_scan(args.manifest_path, cache_dir=args.cache_dir, offline=args.offline)
    except ManifestError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output_path = args.output
    html_path = args.html
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)

    write_report(report, output_path)
    html_content = render_html_report(report, ignore_file=args.ignore_file)
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html_content)

    summary = report["summary"]
    print(f"Scanned {summary['total']} dependencies from {args.manifest_path}")
    print(
        f"Critical={summary['critical']} High={summary['high']} "
        f"Medium={summary['medium']} Low={summary['low']} Safe={summary['safe']}"
    )
    print(f"JSON report written to {output_path}")
    print(f"HTML report written to {html_path}")

    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        report = load_report(args.report_path)
    except (OSError, ValueError) as exc:
        print(f"Error reading report: {exc}", file=sys.stderr)
        return 1

    result = evaluate_gate(report, max_severity=args.max_severity, ignore_file=args.ignore_file)

    for warning in result.warnings:
        print(warning)
    for failure in result.failures:
        print(failure, file=sys.stderr)

    if result.exit_code == 0:
        print("PASS: no unaccepted dependency above the configured severity threshold.")
    else:
        print("FAIL: one or more unaccepted dependencies above the configured severity threshold were found.", file=sys.stderr)

    return result.exit_code


def _cmd_gui(args: argparse.Namespace) -> int:
    import threading
    import webbrowser

    from securechain.gui.server import create_app

    host, port = "127.0.0.1", args.port
    url = f"http://{host}:{port}"
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"SecureChain GUI running at {url}")
    print("Press Control C to stop.")
    create_app().run(host=host, port=port, debug=False)
    return 0


def _cmd_accept(args: argparse.Namespace) -> int:
    if "@" not in args.package_at_version:
        print("Error: expected <package>@<version>, e.g. xml2js@0.4.19", file=sys.stderr)
        return 1
    package, _, version = args.package_at_version.rpartition("@")
    if not package or not version:
        print("Error: expected <package>@<version>, e.g. xml2js@0.4.19", file=sys.stderr)
        return 1

    accepted_by = args.accepted_by or getpass.getuser()
    entry = accept_risk(
        ignore_file=args.ignore_file,
        package=package,
        version=version,
        reason=args.reason,
        accepted_by=accepted_by,
    )
    print(f"Recorded exception: {entry.package}@{entry.version} accepted by {entry.accepted_by} on {entry.date}")
    print(f"Reason: {entry.reason}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securechain", description="SecureChain dependency risk scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a package.json manifest")
    scan_parser.add_argument("manifest_path")
    scan_parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("result/report.json"))
    scan_parser.add_argument("--html", type=pathlib.Path, default=pathlib.Path("result/report.html"))
    scan_parser.add_argument("--cache-dir", default=None)
    scan_parser.add_argument("--offline", action="store_true")
    scan_parser.add_argument("--ignore-file", default=".riskignore.json")
    scan_parser.set_defaults(func=_cmd_scan)

    check_parser = subparsers.add_parser("check", help="CI/CD gate: evaluate a JSON report")
    check_parser.add_argument("report_path")
    check_parser.add_argument("--max-severity", default="safe", choices=["safe", "low", "medium", "high", "critical"])
    check_parser.add_argument("--ignore-file", default=".riskignore.json")
    check_parser.set_defaults(func=_cmd_check)

    accept_parser = subparsers.add_parser("accept", help="Record an accepted risk exception")
    accept_parser.add_argument("package_at_version", metavar="package@version")
    accept_parser.add_argument("--reason", required=True)
    accept_parser.add_argument("--ignore-file", default=".riskignore.json")
    accept_parser.add_argument("--accepted-by", default=None)
    accept_parser.set_defaults(func=_cmd_accept)

    gui_parser = subparsers.add_parser("gui", help="Launch the local preview GUI")
    gui_parser.add_argument("--port", type=int, default=5678)
    gui_parser.add_argument("--no-browser", action="store_true")
    gui_parser.set_defaults(func=_cmd_gui)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
