"""Command-line interface. Report errors cannot silently become a successful scan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .sarif import to_sarif
from .baseline import compare_baseline
from .scanner import Report, SEVERITY_RANK, scan_paths


def text_report(report: Report) -> str:
    lines = [f"Workflow Guard: {report.files_scanned} file(s), "
             f"{len(report.findings)} finding(s), {len(report.errors)} error(s)"]
    for finding in report.findings:
        scope = f"job={finding.job}" if finding.job else "workflow"
        lines.extend([
            f"{finding.file}:{finding.line}:{finding.column} "
            f"[{finding.severity.upper()} {finding.rule_id}] {scope}",
            f"  {finding.message}",
            f"  Evidence: {finding.evidence}",
            f"  Fix: {finding.recommendation}",
        ])
    for error in report.errors:
        lines.append(f"{error.file}:{error.line}:{error.column} [ERROR] {error.message}")
    if not report.findings and not report.errors:
        lines.append("No covered risk patterns detected. This is not a security certification.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect GitHub Actions YAML locally without executing it.")
    parser.add_argument("paths", nargs="+", help="Workflow files or directories of workflow YAML")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root for SARIF relative paths")
    parser.add_argument("--json-output", type=Path, help="Also save a JSON report to this file")
    parser.add_argument('--baseline', type=Path, help='Reviewed JSON report: gate only unmatched findings, retaining all findings')
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="high",
                        help="Exit 1 on findings at or above this severity (default: high)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if args.json_output:
        output = args.json_output.resolve()
        if args.baseline and output == args.baseline.resolve():
            parser.error('JSON output must not replace the reviewed baseline')
        for raw in args.paths:
            input_path = Path(raw)
            if (input_path.is_file() and input_path.resolve() == output) or (
                input_path.is_dir() and input_path.resolve() in output.parents
                and output.suffix.lower() in {".yml", ".yaml"}
            ):
                parser.error("The JSON output must not overwrite an input workflow.")
    report = scan_paths(args.paths)
    value = report.to_dict()
    gated = report.findings
    if args.baseline:
        try:
            gate = compare_baseline(report, args.baseline, args.root)
        except (OSError, ValueError, TypeError, KeyError) as error:
            parser.error('Baseline rejected: ' + str(error))
        value['baseline_gate'] = gate
        gated = [report.findings[index] for index in gate['new_finding_indices']]
    serialized = json.dumps(value, ensure_ascii=False, indent=2)
    if args.json_output:
        try:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(serialized + "\n", encoding="utf-8")
        except OSError:
            print("Cannot write the requested JSON report.", file=sys.stderr)
            return 2
    if args.format == 'sarif':
        sarif = to_sarif(report, args.root)
        if args.baseline:
            sarif['runs'][0].setdefault('properties', {})['baselineGate'] = gate
        print(json.dumps(sarif, ensure_ascii=False, indent=2))
    elif args.format == 'json':
        print(serialized)
    else:
        print(text_report(report))
        if args.baseline:
            print(f"Reviewed baseline gate: {gate['new_findings']} unmatched, {gate['matched_findings']} matched; all findings shown.")
    if report.errors:
        return 2
    if args.fail_on != "none" and any(
        SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[args.fail_on]
        for finding in gated
    ):
        return 1
    return 0
