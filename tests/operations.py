#!/usr/bin/env python3
"""Isolated Docker monitoring, management-key restart and network acceptance."""
import json
import ipaddress
import datetime
import re
import pathlib
import subprocess
import time
import urllib.parse
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    suffix = uuid.uuid4().hex[:12]
    prefix = 'porter-ops-' + suffix
    porter, peer = prefix + ':porter', prefix + ':peer'
    appnet, monitor = prefix + '-app', prefix + '-monitor'
    data, fixture = prefix + '-data', prefix + '-fixture'
    service, prometheus, blackbox = prefix + '-porter', prefix + '-prometheus', prefix + '-blackbox'
    containers, networks, volumes, images = [], [], [], []

    def docker(*args):
        return subprocess.check_output(['docker', *args], cwd=ROOT, text=True,
                                       stderr=subprocess.STDOUT).strip()

    def peer_run(*args, network=monitor, mounts=False):
        command = ['run', '--rm', '--network', network]
        if mounts:
            command += ['--user', '0:0', '-v', fixture + ':/fixture', '-v', data + ':/data']
        return docker(*command, peer, *args)

    def request(url, key=None, network=monitor, method='GET'):
        args = ['request', method, url]
        if key:
            args.append(key)
        return json.loads(peer_run(*args, network=network))

    def wait(test, message, seconds=60):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if test():
                return
            time.sleep(1)
        raise AssertionError(message)

    def query(expression):
        result = request('http://' + prometheus_ip + ':9090/api/v1/query?' + urllib.parse.urlencode({'query': expression}))
        if result['status'] != 200:
            return None
        payload = json.loads(result['body'])
        assert payload['status'] == 'success'
        return payload['data']['result']

    def value(expression, expected):
        results = query(expression)
        return results is not None and len(results) == 1 and float(results[0]['value'][1]) == expected

    def alert(name, expected):
        results = query('ALERTS{alertname="' + name + '",alertstate="firing"}')
        return results is not None and bool(results) == expected

    def evaluated_after(timestamp):
        result = request('http://' + prometheus_ip + ':9090/api/v1/rules?type=alert')
        if result['status'] != 200:
            return False
        groups = json.loads(result['body'])['data']['groups']
        return any(group['name'] == 'porter' and
                   datetime.datetime.fromisoformat(re.sub(r'(\.\d{6})\d+', r'\1', group['lastEvaluation']).replace('Z', '+00:00')).timestamp() > timestamp
                   for group in groups)

    def sidecars():
        for name, image, address, args in [
            (blackbox, 'prom/blackbox-exporter:v0.29.1@sha256:ea1c7aa3ef3f307cd03e85f34abb604478ccb90b567fc690da0cd9776da76b13', blackbox_ip, ['--config.file=/fixture/blackbox.yml', '--web.listen-address=' + blackbox_ip + ':9115']),
            (prometheus, 'prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06', prometheus_ip, ['--config.file=/fixture/prometheus.yml', '--storage.tsdb.path=/prometheus', '--web.listen-address=' + prometheus_ip + ':9090']),
        ]:
            docker('run', '-d', '--name', name, '--user', '65534:65534', '--network', monitor, '--ip', address,
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '-v', fixture + ':/fixture:ro', image, *args)
            containers.append(name)


    try:
        for image, path in [(porter, 'Dockerfile'), (peer, 'tests/operations/Dockerfile')]:
            subprocess.run(['docker', 'build', '-f', path, '-t', image, '.'], cwd=ROOT, check=True)
            images.append(image)
        network_ids = docker('network', 'ls', '-q').split()
        existing = json.loads(docker('network', 'inspect', *network_ids)) if network_ids else []
        occupied = [ipaddress.ip_network(item['Subnet']) for network in existing
                    for item in (network.get('IPAM', {}).get('Config') or []) if item.get('Subnet')]
        # Docker requires a user-configured subnet for explicit container IPs.
        # Select unused private /24s instead of relying on its implicit IPAM pool.
        candidates = [ipaddress.ip_network('10.240.' + str((int(suffix[:2], 16) + offset) % 256) + '.0/24')
                      for offset in range(256)]
        for name in (appnet, monitor):
            subnet = next(candidate for candidate in candidates
                          if not any(candidate.version == other.version and candidate.overlaps(other) for other in occupied))
            docker('network', 'create', '--internal', '--subnet', str(subnet), name)
            occupied.append(subnet)
            networks.append(name)
        for name in (data, fixture):
            docker('volume', 'create', name)
            volumes.append(name)
        def address(network):
            config = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config']
            subnet = next(item['Subnet'] for item in config if ':' not in item['Subnet'])
            return str(ipaddress.ip_network(subnet).network_address + 2)
        ip, app_ip = address(monitor), address(appnet)
        blackbox_ip = str(ipaddress.ip_address(ip) + 1)
        prometheus_ip = str(ipaddress.ip_address(ip) + 2)
        docker('create', '--name', service, '--network', monitor, '--ip', ip, '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '-v', data + ':/data', '-v', fixture + ':/fixture:ro', porter,
               'serve', '-config', '/fixture/porter.json')
        containers.append(service)
        docker('network', 'connect', '--ip', app_ip, appnet, service)
        peer_run('init', ip, mounts=True, network='none')
        peer_run('configure', ip, blackbox_ip, mounts=True, network='none')
        docker('start', service)
        wait(lambda: request('http://' + ip + ':9093/readyz', 'old')['status'] == 200, 'Porter did not become ready')
        sidecars()
        wait(lambda: value('up{job="porter"}', 1) and value('probe_success{job="porter-readiness"}', 1), 'real authenticated scrapes failed')
        monitoring_started = {name: docker('inspect', '--format', '{{.State.StartedAt}}', name) for name in (prometheus, blackbox)}
        # No published management, exporter or Prometheus ports. Application
        # peers can reach only the application listener on their interface.
        for name in (service, blackbox, prometheus):
            bindings = json.loads(docker('inspect', '--format', '{{json .HostConfig.PortBindings}}', name))
            assert not bindings, 'a management port was published'
        for port in (9093, 9115, 9090):
            assert request('http://' + app_ip + ':' + str(port) + '/metrics', network=appnet)['status'] == 0, 'management bound to application interface'
            assert request('http://' + ip + ':' + str(port) + '/metrics', network=appnet)['status'] == 0, 'application peer crossed monitoring network'
        for target_ip, port in ((blackbox_ip, 9115), (prometheus_ip, 9090)):
            assert request('http://' + target_ip + ':' + str(port) + '/metrics', network=appnet)['status'] == 0, 'application peer reached monitoring process'
        for route in ('/metrics', '/readyz', '/version'):
            assert request('http://' + app_ip + ':8083' + route, network=appnet)['status'] == 404
        assert request('http://' + ip + ':9093/metrics', 'proxy')['status'] == 401
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 200
        # A changed mounted key does not change the running Porter's key.
        peer_run('rotate', mounts=True, network='none')
        assert request('http://' + ip + ':9093/readyz', 'old')['status'] == 200
        assert request('http://' + ip + ':9093/readyz', 'new')['status'] == 401
        wait(lambda: value('up{job="porter"}', 0) and value('probe_success{job="porter-readiness"}', 0), 'credential mismatch did not break scrapes')
        wait(lambda: alert('PorterScrapeUnavailable', True) and alert('PorterReadinessFailed', True), 'failure alerts did not fire')
        assert alert('PorterReadinessProbeUnavailable', False), 'healthy exporter misclassified as unavailable'
        docker('stop', '--time', '20', service)
        assert docker('inspect', '--format', '{{.State.ExitCode}}', service) == '0'
        docker('start', service)
        wait(lambda: request('http://' + ip + ':9093/readyz', 'new')['status'] == 200, 'new key not loaded after restart')
        assert request('http://' + ip + ':9093/readyz', 'old')['status'] == 401
        for name, started in monitoring_started.items():
            assert docker('inspect', '--format', '{{.State.StartedAt}}', name) == started, 'monitoring restarted instead of resolving alerts'
        wait(lambda: value('up{job="porter"}', 1) and value('probe_success{job="porter-readiness"}', 1), 'scrapes did not recover')
        recovered_at = time.time()
        wait(lambda: evaluated_after(recovered_at) and alert('PorterScrapeUnavailable', False) and alert('PorterReadinessFailed', False), 'original alerts did not resolve after a fresh rule evaluation')
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 200
        assert request('http://' + app_ip + ':8083/auth', 'proxy', network=appnet)['status'] == 503, 'identity-only auth did not fail closed'
        assert request('http://' + app_ip + ':8083/logout', 'proxy', network=appnet, method='POST')['status'] == 303
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 401
        # Exporter failure is distinct from Porter readiness failure.
        docker('stop', blackbox)
        wait(lambda: alert('PorterReadinessProbeUnavailable', True), 'exporter outage alert did not fire')
        docker('start', blackbox)
        wait(lambda: value('probe_success{job="porter-readiness"}', 1) and alert('PorterReadinessProbeUnavailable', False), 'exporter outage did not recover')
        # Revocation must remain durable through another key-preserving restart.
        docker('stop', '--time', '20', service)
        assert docker('inspect', '--format', '{{.State.ExitCode}}', service) == '0'
        docker('start', service)
        wait(lambda: request('http://' + ip + ':9093/readyz', 'new')['status'] == 200, 'post-logout restart failed')
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 401
        wait(lambda: value('up{job="porter"}', 1) and value('probe_success{job="porter-readiness"}', 1), 'post-logout monitoring failed')
        observations = json.dumps(query('ALERTS')) + json.dumps(query('up'))
        for name in containers:
            observations += docker('logs', name)
        for private in ('m' * 32, 'n' * 32, 'p' * 32, 'C' * 43, 'provider-SECRET', 'fixture@example.test'):
            assert private not in observations, 'secret in monitoring labels or logs'
        print('PASS: authenticated scrapes, isolated interfaces, alerts, key restart, preserved session and logout')
    except Exception as error:
        def safe(text):
            for private in ('m'*32,'n'*32,'p'*32,'C'*43,'provider-SECRET','fixture@example.test'):
                text = text.replace(private,'[redacted]')
            return text
        if isinstance(error, subprocess.CalledProcessError):
            print(safe(error.output or 'container command failed'))
        for name in containers:
            print(name, safe(docker('logs', name)))
        if prometheus in containers:
            print(safe(str(request('http://' + prometheus_ip + ':9090/api/v1/targets'))))
        raise
    finally:
        for name in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in volumes:
            subprocess.run(['docker', 'volume', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in networks:
            subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in images:
            subprocess.run(['docker', 'image', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
