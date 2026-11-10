#!/usr/bin/env python3
"""Bounded Linux capacity and offline recovery acceptance using synthetic sessions."""
import argparse
import json
import pathlib
import platform
import subprocess
import time
import uuid


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
    network = prefix + "-net"
    network_created = False
    checks, timings = [], {}

    def docker(*command):
        return subprocess.check_output(['docker', *command], text=True, stderr=subprocess.STDOUT).strip()

    def helper(command, volume=data):
        return docker('run', '--rm', '--network', 'none', '--user', '0:0', '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128',
                      '-v', volume + ':/data', '-v', configuration + ':/configuration', args.fixture_image, command)

    def peer(*command):
        return json.loads(docker('run', '--rm', '--network', network, '--read-only', '--cap-drop', 'ALL',
                                 '--security-opt', 'no-new-privileges:true', '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128',
                                 '--entrypoint', '/peer', args.fixture_image, *command))

    def request(port, route, *, management=False, token=None, method='GET', transaction=False):
        kind = 'management' if management else 'transaction' if transaction else 'session'
        return peer('request', 'http://porter:' + port + route, method, token or '', kind)['status']

    def start(volume):
        begin = time.monotonic()
        name = prefix + '-' + uuid.uuid4().hex[:6]
        docker('run', '-d', '--name', name, '--network', network, '--network-alias', 'porter', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128', '-v', volume + ':/data', '-v', configuration + ':/config:ro',
               args.porter_image, 'serve', '-config', '/config/porter.json')
        containers.append(name)
        assert not json.loads(docker('inspect', '--format', '{{json .HostConfig.PortBindings}}', name)), 'published a private port'
        public, management = '8083', '9093'
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if request(management, '/readyz', management=True) == 200:
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
        actual = request(public, route, token=token, method=method)
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
        docker('network', 'create', '--internal', network)
        network_created = True
        assert docker('network', 'inspect', '--format', '{{.Internal}}', network) == 'true'
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
        # The bounded peer samples inside the private network, without host ports.
        latency = peer('load', 'http://porter:8083/identity')
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
        assert request(public, callback, token='B', transaction=True) == 400, 'restored callback accepted'
        checks += ['snapshot_revoked_after_backup_not_revived', 'all_restored_sessions_invalid', 'restored_callback_denied']
        stop(name)
        fresh_expiry_ms = int(helper('arm-recovery-session', recovered))
        assert fresh_expiry_ms > (time.time() + 1800) * 1000, 'fresh fixture lifetime is too short'
        name, public, _ = start(recovered)
        status(public, 200, 'F')
        status(public, 303, 'F', '/logout', 'POST')
        stop(name)
        name, public, _ = start(recovered)
        status(public, 401, 'F')
        assert fresh_expiry_ms > (time.time() + 60) * 1000, 'natural expiry could mask failed revocation'
        checks.append('fresh_session_logout_persists')
        stop(name)
        evidence = {'passed': True, 'checks': checks, 'system': platform.system(), 'architecture': platform.machine(),
                    'docker_server_version': docker('version', '--format', '{{.Server.Version}}'),
                    'candidate_image_id': docker('image', 'inspect', '--format', '{{.Id}}', args.porter_image),
                    'limits': {'cpus': 0.5, 'memory_mib': 256, 'pids': 128}, 'latency': latency, 'timings': timings,
                    'network_egress_disabled': True, 'fresh_session_deadline_still_future': True,
                    'synthetic_only': True, 'live_provider_login': False, 'rpo_claimed': False, 'incident_rto_claimed': False}
        args.evidence.write_text(json.dumps(evidence, indent=2) + '\n')
        print('PASS: bounded Linux reads, offline recovery invalidation and persistent logout')
    finally:
        for name in containers:
            subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for volume in reversed(volumes):
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if network_created:
            subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
