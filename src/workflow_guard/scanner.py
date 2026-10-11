"""Inspect YAML nodes so every finding retains an auditable source position."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_FILE_BYTES = 1_048_576
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
FULL_SHA = re.compile(r"[a-fA-F0-9]{40}\Z")
DOCKER_DIGEST = re.compile(r".+@sha256:[a-fA-F0-9]{64}\Z")
HEAD_CONTEXT = re.compile(r"\bgithub\.(?:event\.pull_request\.head\b|head_ref\b)")
EVENT_CONTEXT = re.compile(r"\bgithub\.(?:event\.|head_ref\b)")
SECRET_CONTEXT = re.compile(r"\bsecrets(?:\.|\[|\b)")
ECHO_COMMAND = re.compile(r"(?:^|[;&|])\s*(?:builtin\s+)?echo\b[^\n]*", re.MULTILINE)
STANDARD_TAGS = {f"tag:yaml.org,2002:{name}" for name in (
    "str", "int", "float", "bool", "null", "map", "seq", "timestamp",
    "binary", "set", "omap", "pairs",
)}


class WorkflowLoader(yaml.SafeLoader):
    """Keep `on`, `off`, `yes`, and `no` as strings, without changing SafeLoader."""


WorkflowLoader.yaml_implicit_resolvers = {
    character: [
        (tag, matcher)
        for tag, matcher in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    column: int
    job: str | None
    message: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class ScanError:
    file: str
    line: int
    column: int
    message: str


@dataclass
class Report:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    def to_dict(self) -> dict:
        counts = {severity: 0 for severity in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "schema_version": 1,
            "tool": "workflow-guard",
            "files_scanned": self.files_scanned,
            "summary": {"findings": len(self.findings), "by_severity": counts,
                        "errors": len(self.errors)},
            "findings": [asdict(finding) for finding in self.findings],
            "errors": [asdict(error) for error in self.errors],
        }


def fields(node: Node | None) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        return {}
    return {key.value: value for key, value in node.value if isinstance(key, ScalarNode)}


def scalar(node: Node | None) -> str:
    return node.value if isinstance(node, ScalarNode) else ""


def compact(expression: str) -> str:
    return re.sub(r"\s+", "", expression)


def context_access(expression: str) -> str:
    """Normalize literal bracket property access for heuristic context checks."""
    return re.sub(r"\['([A-Za-z_][A-Za-z0-9_]*)'\]", r".\1", compact(expression))


def structural_error(root: Node, file: str) -> ScanError | None:
    """Reject ambiguous duplicate/merge keys; walk alias graphs without recursion."""
    pending = [root]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if node.tag not in STANDARD_TAGS:
            return ScanError(file, node.start_mark.line + 1, node.start_mark.column + 1,
                             "Unsupported YAML tag; only standard YAML types are accepted.")
        if isinstance(node, MappingNode):
            keys: set[str] = set()
            for key, value in node.value:
                if not isinstance(key, ScalarNode):
                    return ScanError(file, key.start_mark.line + 1,
                                     key.start_mark.column + 1,
                                     "Complex mapping keys are unsupported.")
                if key.value == "<<":
                    return ScanError(file, key.start_mark.line + 1,
                                     key.start_mark.column + 1,
                                     "YAML merge keys are unsupported; expand the mapping before scanning.")
                if key.value in keys:
                    return ScanError(file, key.start_mark.line + 1,
                                     key.start_mark.column + 1,
                                     f"Duplicate mapping key: {key.value[:80]}")
                keys.add(key.value)
                pending.append(key)
                pending.append(value)
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)
    return None


def expression_position(node: ScalarNode, expression: str, source: str,
                        offset: int = 0) -> tuple[int, int]:
    """Map decoded expressions back to original block, folded, or quoted YAML."""
    raw = source[node.start_mark.index:node.end_mark.index]
    preceding = sum(compact(match.group(1)) == compact(expression)
                    for match in EXPRESSION.finditer(node.value[:offset]))
    for match in EXPRESSION.finditer(raw):
        if compact(match.group(1)) == compact(expression):
            if preceding:
                preceding -= 1
                continue
            position = node.start_mark.index + match.start()
            return (source.count("\n", 0, position) + 1,
                    position - source.rfind("\n", 0, position))
    # Escaped YAML may not contain the decoded literal; cite the scalar field.
    return node.start_mark.line + 1, node.start_mark.column + 1


def trigger_names(node: Node | None) -> set[str]:
    if isinstance(node, ScalarNode):
        return {node.value}
    if isinstance(node, SequenceNode):
        return {scalar(item) for item in node.value}
    return set(fields(node))


def scan_text(source: str, file: str = "<memory>") -> Report:
    report = Report(files_scanned=1)
    try:
        root = yaml.compose(source, Loader=WorkflowLoader)
    except (yaml.YAMLError, RecursionError) as error:
        mark = getattr(error, "problem_mark", None)
        report.errors.append(ScanError(
            file, mark.line + 1 if mark else 1, mark.column + 1 if mark else 1,
            getattr(error, "problem", None) or "YAML nesting exceeds parser limits.",
        ))
        return report
    if not isinstance(root, MappingNode):
        report.errors.append(ScanError(file, 1, 1, "A workflow must be a YAML mapping."))
        return report
    error = structural_error(root, file)
    if error:
        report.errors.append(error)
        return report
    workflow = fields(root)
    jobs = workflow.get("jobs")
    if not isinstance(jobs, MappingNode) or not jobs.value:
        report.errors.append(ScanError(file, root.start_mark.line + 1, 1,
                                      "A workflow must contain a nonempty jobs mapping."))
        return report

    def add(rule: str, severity: str, node: Node, job: str | None,
            message: str, evidence: str, recommendation: str,
            position: tuple[int, int] | None = None) -> None:
        line, column = position or (node.start_mark.line + 1, node.start_mark.column + 1)
        finding = Finding(rule, severity, file, line, column, job,
                          message, evidence[:180], recommendation)
        if finding not in report.findings:
            report.findings.append(finding)

    def check_permissions(node: Node | None, job: str | None) -> None:
        if scalar(node) == "write-all":
            add("WG001", "high", node, job,
                "All available GITHUB_TOKEN permissions are writable.",
                "permissions: write-all",
                "Declare only the individual permissions required by this scope.")

    def check_uses(node: Node | None, job: str) -> None:
        if not isinstance(node, ScalarNode) or node.value.startswith("./"):
            return
        reference = node.value
        if reference.startswith("docker://"):
            immutable = bool(DOCKER_DIGEST.fullmatch(reference))
            advice = "Pin the container image to a verified sha256 digest."
        else:
            immutable = "@" in reference and bool(FULL_SHA.fullmatch(reference.rsplit("@", 1)[-1]))
            advice = "Pin the remote action or reusable workflow to a verified full commit SHA."
        if not immutable:
            add("WG005", "medium", node, job,
                "Remote dependency reference is mutable or lacks an immutable pin.",
                reference, advice)

    workflow_permissions = workflow.get("permissions")
    check_permissions(workflow_permissions, None)
    privileged = "pull_request_target" in trigger_names(workflow.get("on"))
    for job_key, job_node in jobs.value:
        job_name = scalar(job_key)
        if not isinstance(job_node, MappingNode):
            report.errors.append(ScanError(file, job_node.start_mark.line + 1,
                                          job_node.start_mark.column + 1,
                                          "Each job must be a mapping."))
            continue
        job = fields(job_node)
        job_permissions = job.get("permissions")
        check_permissions(job_permissions, job_name)
        if job_permissions is None and workflow_permissions is None:
            add("WG002", "medium", job_key, job_name,
                "Job inherits token permissions from repository or organization defaults.",
                "No workflow-level or job-level permissions declaration.",
                "Set explicit workflow permissions, or declare this job's minimal permissions.")
        check_uses(job.get("uses"), job_name)
        steps = job.get("steps")
        if not isinstance(steps, SequenceNode):
            continue
        for step_node in steps.value:
            step = fields(step_node)
            uses = step.get("uses")
            check_uses(uses, job_name)
            if privileged and scalar(uses).lower().startswith("actions/checkout@"):
                for name, value in fields(step.get("with")).items():
                    if name not in {"ref", "repository"} or not isinstance(value, ScalarNode):
                        continue
                    for match in EXPRESSION.finditer(value.value):
                        if HEAD_CONTEXT.search(context_access(match.group(1))):
                            add("WG003", "high", value, job_name,
                                "Privileged pull_request_target workflow checks out pull-request head input.",
                                f"checkout {name}: ${{{{ {match.group(1).strip()} }}}}",
                                "Keep untrusted pull-request code in an unprivileged workflow; review any subsequent execution.",
                                expression_position(value, match.group(1), source, match.start()))
            run = step.get("run")
            if not isinstance(run, ScalarNode):
                continue
            for match in EXPRESSION.finditer(run.value):
                expression = match.group(1)
                if EVENT_CONTEXT.search(context_access(expression)):
                    add("WG004", "high", run, job_name,
                        "Event input is interpolated directly into script source.",
                        "${{ " + expression.strip() + " }}",
                        "Pass untrusted input via env and quote the shell variable; review transformations and shell usage.",
                        expression_position(run, expression, source, match.start()))
            for command in ECHO_COMMAND.finditer(run.value):
                for match in EXPRESSION.finditer(command.group(0)):
                    expression = match.group(1)
                    if SECRET_CONTEXT.search(compact(expression)):
                        add("WG006", "high", run, job_name,
                            "An echo command directly references a secret expression; inspect its output destination.",
                            "${{ " + expression.strip() + " }}",
                            "Avoid printing secret values. Log masking does not guarantee redaction of transformed data.",
                            expression_position(run, expression, source,
                                                command.start() + match.start()))
    report.findings.sort(key=lambda finding: (finding.line, finding.column, finding.rule_id))
    return report


def scan_file(path: Path) -> Report:
    file = str(path)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return Report(errors=[ScanError(file, 1, 1, "File exceeds the 1 MiB scanning limit.")])
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return Report(errors=[ScanError(file, 1, 1, "Cannot read this file as UTF-8 YAML.")])
    return scan_text(source, file)


def scan_paths(paths: Iterable[str | Path]) -> Report:
    result = Report()
    candidates: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            discovered = {p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}}
            if not discovered:
                result.errors.append(ScanError(str(path), 1, 1, "No YAML files found in this directory."))
            candidates.update(discovered)
        elif path.is_file():
            candidates.add(path)
        else:
            result.errors.append(ScanError(str(path), 1, 1, "Path does not exist or is not a file/directory."))
    for path in sorted(candidates, key=str):
        report = scan_file(path)
        result.files_scanned += report.files_scanned
        result.findings.extend(report.findings)
        result.errors.extend(report.errors)
    return result
