#!/usr/bin/env python3
"""Real Porter -> Stargate -> Warden contract acceptance; synthetic local identities."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
STARGATE = 'ghcr.io/soulteary/stargate:1.3.6@sha256:51a5f7b854509f7f6a284ec3ffed9c4f8c787967e84679018fa8a6437819a0a4'
WARDEN = 'ghcr.io/soulteary/warden:1.6.3@sha256:9ac7db4184d922ddaadfa99f9e65a59e88641f08181f6eab83a57c19a9e3234c'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--porter-image', help='prebuilt candidate; default builds this checkout')
    parser.add_argument('--peer-image', help='prebuilt test peer; default builds this checkout')
    parser.add_argument('--evidence', type=pathlib.Path)
    args = parser.parse_args()
    prefix = 'porter-contract-' + uuid.uuid4().hex[:12]
    network, data, fixture = prefix + '-net', prefix + '-data', prefix + '-fixture'
    names = {role: prefix + '-' + role for role in ('porter', 'stargate', 'warden')}
    porter, peer = args.porter_image or prefix + ':porter', args.peer_image or prefix + ':peer'
    containers, volumes, networks, images, checks = [], [], [], [], []

    def docker(*arguments):
        return subprocess.check_output(['docker', *arguments], cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()

    def initialize(command):
        docker('run', '--rm', '--network', 'none', '--user', '0:0', '-v', data + ':/data', '-v', fixture + ':/fixture', peer, command)

    def request(role, route, key=None, method='GET'):
        port = {'porter': 8083, 'stargate': 8080, 'warden': 8081}[role]
        command = ['request', method, 'http://' + role + ':' + str(port) + route]
        if key:
            command.append(key)
        return json.loads(docker('run', '--rm', '--network', network, '--cap-drop', 'ALL', peer, *command))

    def wait(role, route):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if request(role, route)['status'] == 200:
                return
            time.sleep(0.5)
        raise AssertionError(role + ' did not become healthy')

    def auth(expected):
        result = request('porter', '/auth', 'proxy')
        assert result['status'] == expected, result
        output = result.get('headers', {})
        if expected == 200:
            assert output.get('X-Auth-User') == output.get('X-Forwarded-User') == 'porter-fixture-user'
            assert output.get('X-Auth-Role') == 'user'
        else:
            assert not any(key.startswith('X-Auth-') or key == 'X-Forwarded-User' for key in output), 'denial returned identity headers'
        assert not any(key in output for key in ('Set-Cookie', 'X-Stargate-Header-Auth', 'Authorization')), 'upstream credential/cookie crossed boundary'

    def reload_directory(command):
        docker('stop', '--time', '20', names['stargate'], names['warden'])
        initialize(command)
        docker('start', names['warden'])
        wait('warden', '/health')
        docker('start', names['stargate'])
        wait('stargate', '/healthz')

    try:
        for value, image, dockerfile in ((args.porter_image, porter, 'Dockerfile'), (args.peer_image, peer, 'tests/contracts/Dockerfile')):
            if not value:
                subprocess.run(['docker', 'build', '-f', dockerfile, '-t', image, '.'], cwd=ROOT, check=True)
                images.append(image)
        docker('network', 'create', '--internal', network)
        networks.append(network)
        for volume in (data, fixture):
            docker('volume', 'create', volume)
            volumes.append(volume)
        initialize('init')
        with tempfile.TemporaryDirectory(prefix='porter-contract-env-') as directory:
            folder = pathlib.Path(directory)
            settings = {
                'warden': {'PORT': '8081', 'ENVIRONMENT': 'production', 'MERGE_MODE': 'ONLY_LOCAL', 'DATA_FILE': '/fixture/users.json', 'REDIS_ENABLED': 'false', 'REQUIRE_EXPLICIT_USER_ID': 'true', 'API_KEY': 'w' * 32},
                'stargate': {'PORT': '8080', 'AUTH_HOST': 'porter.test', 'CALLBACK_ALLOWED_HOSTS': 'porter.test', 'COOKIE_SECURE': 'true', 'WARDEN_ENABLED': 'true', 'WARDEN_URL': 'http://warden:8081', 'WARDEN_API_KEY': 'w' * 32, 'WARDEN_CACHE_TTL': '1', 'HEADER_AUTH_ENABLED': 'true', 'HEADER_AUTH_SHARED_SECRET': 's' * 32, 'PASSWORD_HEADER_AUTH_ENABLED': 'false', 'PASSWORDS': '', 'HERALD_ENABLED': 'false', 'SESSION_EXCHANGE_SECRET': 'x' * 32},
            }
            for role, image in (('warden', WARDEN), ('stargate', STARGATE), ('porter', porter)):
                command = ['run', '-d', '--name', names[role], '--network', network, '--network-alias', role,
                           '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                           '--cpus', '0.5', '--memory', '256m', '--pids-limit', '128',
                           '-v', fixture + ':/fixture:ro']
                if role in settings:
                    env = folder / (role + '.env')
                    env.write_text(''.join(key + '=' + value + '\n' for key, value in settings[role].items()))
                    env.chmod(0o600)
                    command += ['--env-file', str(env), '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m']
                else:
                    command += ['-v', data + ':/data']
                command.append(image)
                if role == 'porter':
                    command += ['serve', '-config', '/fixture/porter.json']
                docker(*command)
                containers.append(names[role])
                wait(role, '/health' if role == 'warden' else '/healthz')
        auth(200)
        checks.append('bound_identity_and_role')
        assert request('porter', '/auth')['status'] == 401
        assert request('warden', '/user?mail=fixture@example.test')['status'] == 401
        assert request('stargate', '/_auth')['status'] in (401, 403)
        checks.append('forged_headers_and_direct_upstream_denied')
        reload_directory('reassign')
        auth(403)
        checks.append('contact_reassignment_denied')
        reload_directory('disable')
        result = request('porter', '/auth', 'proxy')
        assert result['status'] in (401, 403, 503), result
        assert not any(key.startswith('X-Auth-') or key == 'X-Forwarded-User' for key in result.get('headers', {}))
        checks.append('inactive_directory_identity_denied')
        reload_directory('restore')
        auth(200)
        assert request('porter', '/logout', 'proxy', 'POST')['status'] == 303
        auth(401)
        docker('stop', '--time', '20', names['porter'])
        docker('start', names['porter'])
        wait('porter', '/healthz')
        auth(401)
        checks.append('logout_survives_restart')
        for container in containers:
            assert not json.loads(docker('inspect', '--format', '{{json .HostConfig.PortBindings}}', container)), 'published a private service port'
        evidence = {'passed': True, 'checks': checks, 'upstream_images': {'stargate': STARGATE, 'warden': WARDEN},
                    'candidate_image_id': docker('image', 'inspect', '--format', '{{.Id}}', porter),
                    'synthetic_only': True, 'live_provider_login': False, 'limits': {'cpus_per_service': 0.5, 'memory_mib_per_service': 256, 'pids_per_service': 128}}
        if args.evidence:
            args.evidence.write_text(json.dumps(evidence, indent=2) + '\n')
        print('PASS: real Porter/Stargate/Warden identity, denial, reassignment and persistent logout contracts')
    except subprocess.CalledProcessError:
        # Env files and credentials never enter command arguments or diagnostics.
        raise RuntimeError('contract container command failed; inspect test containers privately') from None
    finally:
        for container in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', '-v', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for volume in volumes:
            subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for item in networks:
            subprocess.run(['docker', 'network', 'rm', item], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for image in images:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
