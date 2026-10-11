import unittest
from pathlib import Path
import tempfile
from workflow_guard.scanner import scan_paths
from workflow_guard.sarif import to_sarif
class SarifTests(unittest.TestCase):
    def test_relative_escaped_location_and_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'space file.yml'
            path.write_text('on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n')
            report=scan_paths([str(path)])
            sarif=to_sarif(report,root);run=sarif['runs'][0]
            self.assertEqual(sarif['version'],'2.1.0')
            self.assertTrue(run['invocations'][0]['executionSuccessful'])
            for result in run['results']:
                location=result['locations'][0]['physicalLocation']
                self.assertEqual(location['artifactLocation']['uri'],'space%20file.yml')
                self.assertGreater(location['region']['startLine'],0)
            path.write_text('jobs: [unterminated')
            run=to_sarif(scan_paths([str(path)]),root)['runs'][0]
            self.assertFalse(run['invocations'][0]['executionSuccessful'])
            self.assertTrue(run['invocations'][0]['toolExecutionNotifications'])
