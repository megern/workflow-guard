"""Optional reviewed baselines affect the exit gate, never hide findings."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from .scanner import Finding, Report, SEVERITY_RANK


def identity(finding, root):
    path = Path(finding.file)
    path = path.resolve() if path.is_absolute() else (root / path).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Baseline comparison requires all workflows inside --root')
    return (str(path.relative_to(root)), finding.rule_id, finding.severity,
            finding.job, finding.message, finding.evidence)


def compare_baseline(report: Report, path: Path, root: Path):
    raw = path.read_bytes()
    previous = json.loads(raw)
    if not isinstance(previous, dict) or previous.get('schema_version') != 1 or previous.get('tool') != 'workflow-guard':
        raise ValueError('Expected a version 1 Workflow Guard JSON report')
    if previous.get('errors') != [] or not isinstance(previous.get('findings'), list):
        raise ValueError('Baseline must contain findings and no scan errors')
    root = root.resolve()
    counts = Counter()
    for value in previous['findings']:
        if not isinstance(value, dict) or set(value) != set(Finding.__dataclass_fields__):
            raise ValueError('Invalid baseline finding fields')
        if value['severity'] not in SEVERITY_RANK or any(not isinstance(value[k], str)
                or not value[k].strip() for k in ('rule_id', 'file', 'message', 'evidence', 'recommendation')):
            raise ValueError('Invalid baseline finding strings')
        if value['job'] is not None and not isinstance(value['job'], str):
            raise ValueError('Invalid baseline job')
        if any(type(value[k]) is not int or value[k] < 1 for k in ('line', 'column')):
            raise ValueError('Invalid baseline position')
        counts[identity(Finding(**value), root)] += 1
    unmatched = []
    for index, finding in enumerate(report.findings):
        key = identity(finding, root)
        if counts[key]:
            counts[key] -= 1
        else:
            unmatched.append(index)
    return {'baseline_sha256': hashlib.sha256(raw).hexdigest(),
            'new_finding_indices': unmatched, 'new_findings': len(unmatched),
            'matched_findings': len(report.findings) - len(unmatched),
            'scope': 'Exit severity gate applies to unmatched findings; all findings remain reported. Positions may change. Duplicate instances use multiset counts. A baseline is a caller-reviewed exception, not a security certification.'}
