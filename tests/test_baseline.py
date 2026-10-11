from dataclasses import replace
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from workflow_guard.baseline import compare_baseline
from workflow_guard.scanner import Finding, Report
from workflow_guard.cli import main


class BaselineTests(unittest.TestCase):
    def test_positions_can_move_but_duplicate_instances_are_not_hidden(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            finding = Finding('WG-fixture', 'high', str(root / 'a.yml'), 1, 1, 'build', 'risk', 'observed', 'fix')
            path = root / 'baseline.json'
            path.write_text(json.dumps(Report(1, [finding]).to_dict()))
            current = Report(1, [replace(finding, line=20), finding])
            result = compare_baseline(current, path, root)
            self.assertEqual(result['new_finding_indices'], [1])
            self.assertEqual(len(current.findings), 2)

    def test_changed_evidence_and_severity_are_new(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            finding = Finding('WG-fixture', 'medium', str(root / 'a.yml'), 1, 1, None, 'risk', 'original', 'fix')
            path = root / 'baseline.json'
            path.write_text(json.dumps(Report(1, [finding]).to_dict()))
            for changed in (replace(finding, severity='high'), replace(finding, evidence='changed')):
                self.assertEqual(compare_baseline(Report(1, [changed]), path, root)['new_findings'], 1)

    def test_baseline_errors_and_outside_root_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            finding = Finding('WG-fixture', 'high', '/outside/a.yml', 1, 1, None, 'risk', 'observed', 'fix')
            path = root / 'baseline.json'
            value = Report(1, [finding]).to_dict()
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'inside'):
                compare_baseline(Report(), path, root)
            value['errors'] = [{'message': 'broken YAML'}]
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'no scan errors'):
                compare_baseline(Report(), path, root)

    def test_exit_gate_retains_old_findings_and_rejects_new_risks_and_parse_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);workflow=root/'a.yml';baseline=root/'baseline.json'
            text='on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n'
            workflow.write_text(text)
            output=io.StringIO()
            with redirect_stdout(output):
                original_exit=main([str(workflow),'--format','json'])
            self.assertEqual(original_exit,1)
            original=json.loads(output.getvalue());baseline.write_text(output.getvalue())
            args=[str(workflow),'--format','json','--baseline',str(baseline),'--root',str(root)]
            output=io.StringIO()
            with redirect_stdout(output):self.assertEqual(main(args),0)
            current=json.loads(output.getvalue())
            self.assertEqual(current['findings'],original['findings'])
            self.assertEqual(current['baseline_gate']['new_findings'],0)
            workflow.write_text(text.replace('echo ok','echo ${{ github.event.issue.title }}'))
            with redirect_stdout(io.StringIO()):self.assertEqual(main(args),1)
            workflow.write_text('jobs: [')
            with redirect_stdout(io.StringIO()):self.assertEqual(main(args),2)
