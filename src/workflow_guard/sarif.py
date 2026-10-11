"""Local SARIF 2.1.0 export. No upload or hosted workflow execution."""
from pathlib import Path
from urllib.parse import quote
from . import __version__


def to_sarif(report, root):
    root = Path(root).resolve()
    rules = sorted({finding.rule_id for finding in report.findings})
    results = []
    for finding in report.findings:
        path = Path(finding.file).resolve()
        uri = quote(path.relative_to(root).as_posix(), safe='/') if path.is_relative_to(root) else path.as_uri()
        results.append({'ruleId': finding.rule_id, 'ruleIndex': rules.index(finding.rule_id),
                        'level': {'high': 'error', 'medium': 'warning', 'low': 'note'}[finding.severity],
                        'message': {'text': finding.message + ' ' + finding.recommendation},
                        'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri},
                            'region': {'startLine': max(1, finding.line), 'startColumn': max(1, finding.column)}}}],
                        'properties': {'evidence': finding.evidence, 'job': finding.job}})
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
            'runs': [{'tool': {'driver': {'name': 'Workflow Guard', 'version': __version__,
                        'informationUri': 'https://github.com/megern/workflow-guard',
                        'rules': [{'id': rule} for rule in rules]}},
                      'columnKind': 'unicodeCodePoints', 'results': results, 'invocations': [{'executionSuccessful': not report.errors,
                        'toolExecutionNotifications': [{'level': 'error', 'message': {'text': error.message},
                          'descriptor': {'id': 'workflow_parse_error'}} for error in report.errors]}]}]}
