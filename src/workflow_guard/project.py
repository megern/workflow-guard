"""Repository scan, reviewed-baseline gate and local review bundle."""
import argparse
import hashlib
import json
from pathlib import Path
from .scanner import Report, ScanError, scan_text, MAX_FILE_BYTES, SEVERITY_RANK
from .baseline import compare_baseline
from .report_bundle import write_bundle

def inspect_project(root, config=None):
    root = Path(root).resolve()
    config = config or {}
    if set(config) - {'fail_on', 'baseline'}:
        raise ValueError('Unknown project policy fields')
    severity = config.get('fail_on', 'high')
    if severity not in ('none', 'low', 'medium', 'high'):
        raise ValueError('Invalid fail_on policy')
    directory = root / '.github/workflows'
    paths = sorted(set(directory.glob('*.yml')) | set(directory.glob('*.yaml')))
    if not paths:
        raise ValueError('No repository workflows found')
    report = Report()
    hashes = {}
    for path in paths:
        if not path.resolve().is_relative_to(root):
            raise ValueError('Workflow symlink leaves repository')
        with path.open('rb') as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('Workflow exceeds size limit')
        hashes[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
        try:
            current = scan_text(raw.decode('utf-8'), str(path))
        except UnicodeError:
            current = Report(files_scanned=1, errors=[ScanError(str(path), 1, 1, 'Workflow is not UTF-8')])
        report.files_scanned += current.files_scanned
        report.findings.extend(current.findings)
        report.errors.extend(current.errors)
    value = report.to_dict()
    gated = report.findings
    if config.get('baseline'):
        baseline = (root / config['baseline']).resolve()
        if not baseline.is_relative_to(root):
            raise ValueError('Reviewed baseline must be inside repository')
        gate = compare_baseline(report, baseline, root)
        value['baseline_gate'] = gate
        gated = [report.findings[i] for i in gate['new_finding_indices']]
    value['input_sha256'] = hashes
    value['policy'] = {'fail_on': severity}
    value['exit_code'] = 2 if report.errors else int(severity != 'none' and any((SEVERITY_RANK[f.severity] >= SEVERITY_RANK[severity] for f in gated)))
    value['scope'] = 'Static covered-pattern review; workflows are never executed. All findings and errors remain visible.'
    return value

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--config', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        config = json.loads(a.config.read_text()) if a.config else {}
        if not isinstance(config, dict):
            raise ValueError('Policy must be an object')
        report = inspect_project(a.root, config)
        write_bundle(a.output, report, 'Workflow Guard repository review')
        print(json.dumps(report['summary']))
        return report['exit_code']
    except (ValueError, OSError, TypeError) as e:
        p.exit(2, str(e) + '\n')
if __name__ == '__main__':
    raise SystemExit(main())
