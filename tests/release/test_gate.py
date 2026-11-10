import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_image', ROOT / 'tools/release-image.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
IMAGE, REPOSITORY = 'ghcr.io/soulteary/porter', 'soulteary/porter'


class ReleaseGate(unittest.TestCase):
    def exercise(self, fail=None, platforms=('amd64', 'arm64'), promote=True, tamper_promotion=False):
        manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                               'manifests': [{'platform': {'os': 'linux', 'architecture': arch}} for arch in platforms]}).encode()
        digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if fail and fail(argv):
                raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0)

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(gate.subprocess, 'run', side_effect=run), mock.patch.object(gate.subprocess, 'check_output', side_effect=lambda command: b'{}' if tamper_promotion and command[-1] == IMAGE + ':v0.2.0' else manifest) as inspect:
            try:
                gate.release(IMAGE, digest, REPOSITORY, 'v0.2.0', pathlib.Path(directory), promote)
            except (ValueError, subprocess.CalledProcessError) as error:
                return calls, error, inspect.call_args_list, digest
        return calls, None, inspect.call_args_list, digest

    def test_success_checks_both_exact_platforms_before_promotion(self):
        calls, error, inspections, digest = self.exercise()
        self.assertIsNone(error)
        scans = [call for call in calls if call[0] == 'trivy']
        self.assertEqual(len(scans), 6)
        self.assertEqual({call[call.index('--platform') + 1] for call in scans}, {'linux/amd64', 'linux/arm64'})
        self.assertTrue(all(call[-1] == IMAGE + '@' + digest for call in scans))
        self.assertEqual(calls[-2][0:3], ['gh', 'attestation', 'verify'])
        self.assertEqual(calls[-1][0:4], ['docker', 'buildx', 'imagetools', 'create'])
        self.assertIn(IMAGE + ':v0.2.0', calls[-1])
        self.assertEqual(inspections[-1].args[0][-1], IMAGE + ':v0.2.0')

    def test_failure_never_assigns_a_version_tag(self):
        for failure in ('amd64', 'arm64', 'attestation'):
            with self.subTest(failure=failure):
                def fail(call):
                    return ((call[0] == 'trivy' and '--exit-code' in call and 'linux/' + failure in call)
                            or (failure == 'attestation' and call[0] == 'gh'))
                calls, error, _, _ = self.exercise(fail)
                self.assertIsInstance(error, subprocess.CalledProcessError)
                self.assertFalse(any(call[0] == 'docker' for call in calls))

    def test_scanner_error_or_missing_platform_blocks_release(self):
        calls, error, _, _ = self.exercise(lambda call: call[0] == 'trivy')
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertFalse(any(call[0] in ('gh', 'docker') for call in calls))
        calls, error, _, _ = self.exercise(platforms=('amd64',))
        self.assertIsInstance(error, ValueError)
        self.assertFalse(calls)

    def test_changed_promoted_manifest_fails_final_verification(self):
        calls, error, _, _ = self.exercise(tamper_promotion=True)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(calls[-1][0:4], ['docker', 'buildx', 'imagetools', 'create'])

    def test_check_mode_cannot_publish(self):
        calls, error, _, _ = self.exercise(promote=False)
        self.assertIsNone(error)
        self.assertTrue(all(call[0] == 'trivy' for call in calls))

    def test_mismatched_manifest_is_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(gate.subprocess, 'check_output', return_value=b'{}'), mock.patch.object(gate.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                gate.release(IMAGE, 'sha256:' + '0' * 64, REPOSITORY, 'v0.2.0', pathlib.Path(directory), True)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
