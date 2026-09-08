import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
# Pure interface tests run on Linux too; collection integration runs on Windows.
if os.name != 'nt':
    import types
    sys.modules['winreg'] = types.SimpleNamespace(HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2)
import windows_ir_reporter as reporter
from windows_ir_app import validate_options, create_run_folder


class DesktopTests(unittest.TestCase):
    def test_invalid_options(self):
        for days, events in [('bad', 400), (0, 400), (366, 400), (3, 0), (3, 100001)]:
            with self.subTest(days=days, events=events), self.assertRaises(ValueError):
                validate_options(days, events)
        self.assertEqual(validate_options('3', '400'), (3, 400))

    def test_separate_runs_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = create_run_folder(Path(tmp) / 'reports with spaces')
            evidence = first / 'evidence.txt'
            evidence.write_text('original')
            second = create_run_folder(first.parent)
            self.assertNotEqual(first, second)
            self.assertEqual(evidence.read_text(), 'original')

    def test_cli_rejects_invalid_ranges_before_collection(self):
        for args in [['--days', '0'], ['--max-events', '-1']]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                reporter.main(args)
            self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows collection boundary')
    def test_browser_opt_out_and_report_generation(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            for name, value in [('powershell_available', True), ('is_admin', False),
                                ('collect_basic_system_info', {}),
                                ('collect_event_log', {'exists': False, 'events': []}),
                                ('collect_run_keys', []), ('collect_startup_items', [])]:
                stack.enter_context(patch.object(reporter, name, return_value=value))
            browser = stack.enter_context(patch.object(reporter, 'collect_browser_history'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(reporter.main(['--outdir', tmp, '--skip-browser-history']), 0)
            browser.assert_not_called()
            for name in ['windows_ir_analyst_report.html', 'windows_ir_stakeholder_summary.html', 'windows_ir_report.json']:
                self.assertTrue((Path(tmp) / name).is_file(), name)


if __name__ == '__main__':
    unittest.main()
