from pathlib import Path
import tempfile
import unittest
from workflow_guard.project import inspect_project
class ProjectTests(unittest.TestCase):
    def test_errors_cannot_pass_policy_and_input_identity_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/'.github/workflows';folder.mkdir(parents=True)
            (folder/'bad.yml').write_text('jobs: [broken')
            report=inspect_project(root,{'fail_on':'none'})
            self.assertEqual(report['exit_code'],2);self.assertIn('.github/workflows/bad.yml',report['input_sha256'])
    def test_external_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo';folder=root/'.github/workflows';folder.mkdir(parents=True)
            target=Path(temp)/'outside.yml';target.write_text('jobs: {}');(folder/'link.yml').symlink_to(target)
            with self.assertRaises(ValueError):inspect_project(root)
