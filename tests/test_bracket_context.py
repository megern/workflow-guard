import unittest
from workflow_guard.scanner import scan_text
class BracketAccessTests(unittest.TestCase):
 def test_script_interpolation_bracket_context_preserves_location(self):
  source="on: push\npermissions: read-all\njobs:\n  test:\n    steps:\n      - run: echo ${{ github['event']['issue']['title'] }}\n"
  report=scan_text(source)
  risk=[f for f in report.findings if f.rule_id=='WG004']
  self.assertEqual(len(risk),1);self.assertEqual(risk[0].line,6);self.assertIn("['event']",risk[0].evidence)
 def test_checkout_bracket_head_flagged(self):
  source="on: pull_request_target\npermissions: read-all\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@"+'a'*40+"\n        with:\n          ref: ${{ github['event'].pull_request['head'].sha }}\n"
  self.assertIn('WG003',[f.rule_id for f in scan_text(source).findings])
 def test_env_passed_input_not_script_interpolation(self):
  source="on: push\npermissions: read-all\njobs:\n  test:\n    steps:\n      - env:\n          TITLE: ${{ github['event']['issue']['title'] }}\n        run: echo \"$TITLE\"\n"
  self.assertNotIn('WG004',[f.rule_id for f in scan_text(source).findings])
