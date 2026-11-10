#!/usr/bin/env python3
"""Bounded Linux capacity and offline recovery acceptance using synthetic sessions."""
import argparse
import concurrent.futures
import json
import pathlib
import platform
import statistics
import subprocess
import time
import uuid
import urllib.error
import urllib.request

from production import request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--porter-image', required=True)
    parser.add_argument('--fixture-image', required=True)
    parser.add_argument('--recovery-image', required=True)
    parser.add_argument('--evidence', type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Linux', 'run on a Linux Docker host'
    prefix = 'porter-linux-' + uuid.uuid4().hex[:12]
    data, recovered, configuration, backup = [prefix + '-' + name for name in ('data', 'recovered', 'config', 'backup')]
    volumes, containers = [], []
    checks, timings = [], {}

    def docker(*command):
        return subprocess.check_output(['docker', *command], text=True, stderr=subprocess.STDOUT).strip()

    def helper(command, volume=data):
        return docker('run', '--rm', '--network', 'none', '--user', '0:0', '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128',
                      '-v', volume + ':/data', '-v', configuration + ':/configuration', args.fixture_image, command)

    def start(volume):
        begin = time.monotonic()
        name = prefix + '-' + uuid.uuid4().hex[:6]
        docker('run', '-d', '--name', name, '--network', 'bridge', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128', '-v', volume + ':/data', '-v', configuration + ':/config:ro',
               '-p', '127.0.0.1::8083', '-p', '127.0.0.1::9093', args.porter_image, 'serve', '-config', '/config/porter.json')
        containers.append(name)
        ports = json.loads(docker('inspect', '--format', '{{json .NetworkSettings.Ports}}', name))
        for value in ports.values():
            assert all(binding['HostIp'] == '127.0.0.1' for binding in value)
        public, management = [ports[str(port) + '/tcp'][0]['HostPort'] for port in (8083, 9093)]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if request(management, '/readyz', management=True)[0] == 200:
                    return name, public, round(time.monotonic() - begin, 3)
            except OSError:
                pass
            time.sleep(0.2)
        raise AssertionError('candidate did not become ready')

    def stop(name):
        docker('stop', '--time', '20', name)
        assert docker('inspect', '--format', '{{.State.ExitCode}}', name) == '0'
        logs = docker('logs', name)
        for secret in ('FIXTURE_SECRET', 'fixture@example.test', 'p' * 32, 'm' * 32, *(letter * 43 for letter in 'LCREF')):
            assert secret not in logs, 'sensitive value in logs'
        docker('rm', name)
        containers.remove(name)

    def status(public, expected, token, route='/identity', method='GET'):
        actual = request(public, route, token=token, method=method)[0]
        assert actual == expected, (route, actual, expected)

    def recovery(command, source, destination, digest=None):
        arguments = [command, '--stopped', '--source', source, '--destination', destination]
        if digest:
            arguments += ['--sha256', digest]
        begin = time.monotonic()
        result = docker('run', '--rm', '--network', 'none', '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL',
                        '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128',
                        '-v', data + ':/source:ro', '-v', backup + ':/backup', '-v', recovered + ':/recovered', args.recovery_image, *arguments)
        timings[command + '_seconds'] = round(time.monotonic() - begin, 3)
        assert result.startswith('sha256=') and len(result) == 71, 'unexpected recovery output'
        return result[7:]

    try:
        for volume in (data, recovered, configuration, backup):
            docker('volume', 'create', volume)
            volumes.append(volume)
        helper('seed')
        # The test helper prepares private directories, without copying any state.
        helper('prepare-directory', recovered)
        helper('prepare-directory', backup)
        name, public, timings['initial_ready_seconds'] = start(data)
        status(public, 200, 'L')
        status(public, 200, 'C')
        status(public, 401, 'R')
        status(public, 401, 'E')
        # Fixed 10 QPS for 20 seconds; never an unbounded saturation test.
        samples = []
        def sample():
            begin = time.monotonic()
            status(public, 200, 'C')
            return (time.monotonic() - begin) * 1000
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            begin = time.monotonic()
            for index in range(200):
                time.sleep(max(0, begin + index / 10 - time.monotonic()))
                futures.append(executor.submit(sample))
            samples = [future.result() for future in futures]
        samples.sort()
        latency = {'requests': len(samples), 'offered_qps': 10, 'duration_seconds': round(time.monotonic() - begin, 3),
                   'p50_ms': round(statistics.median(samples), 3), 'p95_ms': round(samples[189], 3), 'p99_ms': round(samples[197], 3)}
        checks.append('bounded_identity_reads')
        stop(name)
        digest = recovery('backup', '/source/porter.db', '/backup/snapshot.db')
        name, public, _ = start(data)
        status(public, 303, 'L', '/logout', 'POST')
        status(public, 401, 'L')
        stop(name)
        recovery('restore', '/backup/snapshot.db', '/recovered/porter.db', digest)
        helper('verify-recovered', recovered)
        name, public, timings['restored_ready_seconds'] = start(recovered)
        for token in 'LCRE':
            status(public, 401, token)
        status(public, 401, 'L', '/auth')
        # Pending state in the snapshot must not survive disaster recovery.
        callback = '/callback/github?state=' + 'P' * 43 + '&code=fixture-code'
        req = urllib.request.Request('http://127.0.0.1:' + public + callback, headers={'Host': 'porter.test', 'Cookie': '__Host-porter_transaction=' + 'B' * 43})
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = client.open(req, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == 400, 'restored callback accepted'
        checks += ['snapshot_revoked_after_backup_not_revived', 'all_restored_sessions_invalid', 'restored_callback_denied']
        stop(name)
        helper('arm-expiry', recovered)
        name, public, _ = start(recovered)
        status(public, 200, 'F')
        status(public, 303, 'F', '/logout', 'POST')
        stop(name)
        name, public, _ = start(recovered)
        status(public, 401, 'F')
        checks.append('fresh_session_logout_persists')
        stop(name)
        evidence = {'passed': True, 'checks': checks, 'system': platform.system(), 'architecture': platform.machine(),
                    'docker_server_version': docker('version', '--format', '{{.Server.Version}}'),
                    'candidate_image_id': docker('image', 'inspect', '--format', '{{.Id}}', args.porter_image),
                    'limits': {'cpus': 0.5, 'memory_mib': 256, 'pids': 128}, 'latency': latency, 'timings': timings,
                    'synthetic_only': True, 'live_provider_login': False, 'rpo_claimed': False, 'incident_rto_claimed': False}
        args.evidence.write_text(json.dumps(evidence, indent=2) + '\n')
        print('PASS: bounded Linux reads, offline recovery invalidation and persistent logout')
    finally:
        for name in containers:
            subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for volume in reversed(volumes):
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
