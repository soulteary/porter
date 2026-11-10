#!/usr/bin/env python3
"""Check an immutable image index; optionally verify provenance and promote it."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

PLATFORMS = ('amd64', 'arm64')


def inspect(reference, digest):
    raw = subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', '--raw', reference])
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('registry manifest digest differs from candidate')
    manifest = json.loads(raw)
    supported = {(entry.get('platform', {}).get('os'), entry.get('platform', {}).get('architecture'))
                 for entry in manifest.get('manifests', [])}
    if not {('linux', arch) for arch in PLATFORMS}.issubset(supported):
        raise ValueError('candidate does not contain both required Linux architectures')
    return raw


def release(image, digest, repository, version, reports, promote=False):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid repository')
    if image != 'ghcr.io/' + repository.lower() or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('invalid immutable candidate reference')
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?', version):
        raise ValueError('invalid release version')
    reference = image + '@' + digest
    manifest = inspect(reference, digest)
    reports.mkdir(mode=0o700, parents=True, exist_ok=True)
    (reports / 'manifest.json').write_bytes(manifest)
    (reports / 'subject.txt').write_text(reference + '\n')
    for arch in PLATFORMS:
        common = ['trivy', 'image', '--image-src', 'remote', '--platform', 'linux/' + arch,
                  '--scanners', 'vuln', '--ignorefile', '/dev/null']
        subprocess.run(common + ['--format', 'cyclonedx', '--output', str(reports / (arch + '.cdx.json')), reference], check=True)
        subprocess.run(common + ['--format', 'json', '--output', str(reports / (arch + '.vulnerabilities.json')), reference], check=True)
        subprocess.run(common + ['--severity', 'HIGH,CRITICAL', '--ignore-unfixed', '--exit-code', '1', reference], check=True)
    if not promote:
        return
    # No version tag is created if either scan or provenance verification fails.
    subprocess.run(['gh', 'attestation', 'verify', 'oci://' + reference, '--repo', repository,
                    '--signer-workflow', repository + '/.github/workflows/release.yml'], check=True)
    subprocess.run(['docker', 'buildx', 'imagetools', 'create', '--prefer-index=false',
                    '--tag', image + ':' + version, reference], check=True)
    inspect(image + ':' + version, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--reports', type=pathlib.Path, default=pathlib.Path('release-reports'))
    parser.add_argument('--promote', action='store_true')
    args = parser.parse_args()
    release(args.image, args.digest, args.repository, args.version, args.reports, args.promote)


if __name__ == '__main__':
    main()
