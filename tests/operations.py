#!/usr/bin/env python3
"""Isolated Docker monitoring, management-key restart and network acceptance."""
import json
import ipaddress
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
        result = request('http://' + ip + ':9090/api/v1/query?' + urllib.parse.urlencode({'query': expression}))
        if result['status'] != 200:
            return []
        payload = json.loads(result['body'])
        assert payload['status'] == 'success'
        return payload['data']['result']

    def value(expression, expected):
        results = query(expression)
        return len(results) == 1 and float(results[0]['value'][1]) == expected

    def alert(name, expected):
        return bool(query('ALERTS{alertname="' + name + '",alertstate="firing"}')) == expected

    def sidecars():
        for name, image, args in [
            (blackbox, 'prom/blackbox-exporter:v0.29.1@sha256:ea1c7aa3ef3f307cd03e85f34abb604478ccb90b567fc690da0cd9776da76b13', ['--config.file=/fixture/blackbox.yml', '--web.listen-address=' + ip + ':9115']),
            (prometheus, 'prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06', ['--config.file=/fixture/prometheus.yml', '--storage.tsdb.path=/prometheus', '--web.listen-address=' + ip + ':9090']),
        ]:
            docker('run', '-d', '--name', name, '--user', '65534:65534', '--network', 'container:' + service,
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '-v', fixture + ':/fixture:ro', image, *args)
            containers.append(name)

    def remove_sidecars():
        for name in (prometheus, blackbox):
            docker('rm', '-f', name)
            containers.remove(name)

    try:
        for image, path in [(porter, 'Dockerfile'), (peer, 'tests/operations/Dockerfile')]:
            subprocess.run(['docker', 'build', '-f', path, '-t', image, '.'], cwd=ROOT, check=True)
            images.append(image)
        for name in (appnet, monitor):
            docker('network', 'create', '--internal', name)
            networks.append(name)
        for name in (data, fixture):
            docker('volume', 'create', name)
            volumes.append(name)
        def address(network):
            config = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config']
            subnet = next(item['Subnet'] for item in config if ':' not in item['Subnet'])
            return str(ipaddress.ip_network(subnet).network_address + 2)
        ip, app_ip = address(monitor), address(appnet)
        docker('create', '--name', service, '--network', monitor, '--ip', ip, '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '-v', data + ':/data', '-v', fixture + ':/fixture:ro', porter,
               'serve', '-config', '/fixture/porter.json')
        containers.append(service)
        docker('network', 'connect', '--ip', app_ip, appnet, service)
        peer_run('init', ip, mounts=True, network='none')
        peer_run('configure', ip, mounts=True, network='none')
        docker('start', service)
        wait(lambda: request('http://' + ip + ':9093/readyz', 'old')['status'] == 200, 'Porter did not become ready')
        sidecars()
        wait(lambda: value('up{job="porter"}', 1) and value('probe_success{job="porter-readiness"}', 1), 'real authenticated scrapes failed')
        # No published management, exporter or Prometheus ports. Application
        # peers can reach only the application listener on their interface.
        for name in (service, blackbox, prometheus):
            bindings = json.loads(docker('inspect', '--format', '{{json .HostConfig.PortBindings}}', name))
            assert not bindings, 'a management port was published'
        for port in (9093, 9115, 9090):
            assert request('http://' + app_ip + ':' + str(port) + '/metrics', network=appnet)['status'] == 0, 'management bound to application interface'
            assert request('http://' + ip + ':' + str(port) + '/metrics', network=appnet)['status'] == 0, 'application peer crossed monitoring network'
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
        remove_sidecars()
        docker('stop', '--time', '20', service)
        assert docker('inspect', '--format', '{{.State.ExitCode}}', service) == '0'
        docker('start', service)
        wait(lambda: request('http://' + ip + ':9093/readyz', 'new')['status'] == 200, 'new key not loaded after restart')
        assert request('http://' + ip + ':9093/readyz', 'old')['status'] == 401
        sidecars()
        wait(lambda: value('up{job="porter"}', 1) and value('probe_success{job="porter-readiness"}', 1), 'scrapes did not recover')
        wait(lambda: alert('PorterScrapeUnavailable', False) and alert('PorterReadinessFailed', False), 'alerts did not resolve')
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 200
        assert request('http://' + app_ip + ':8083/auth', 'proxy', network=appnet)['status'] == 503, 'identity-only auth did not fail closed'
        assert request('http://' + app_ip + ':8083/logout', 'proxy', network=appnet, method='POST')['status'] == 303
        assert request('http://' + app_ip + ':8083/identity', 'proxy', network=appnet)['status'] == 401
        # Exporter failure is distinct from Porter readiness failure.
        docker('stop', blackbox)
        wait(lambda: alert('PorterReadinessProbeUnavailable', True), 'exporter outage alert did not fire')
        docker('start', blackbox)
        wait(lambda: value('probe_success{job="porter-readiness"}', 1) and alert('PorterReadinessProbeUnavailable', False), 'exporter outage did not recover')
        observations = json.dumps(query('ALERTS')) + json.dumps(query('up'))
        for name in containers:
            observations += docker('logs', name)
        for private in ('m' * 32, 'n' * 32, 'p' * 32, 'C' * 43, 'provider-SECRET', 'fixture@example.test'):
            assert private not in observations, 'secret in monitoring labels or logs'
        print('PASS: authenticated scrapes, isolated interfaces, alerts, key restart, preserved session and logout')
    except Exception:
        def safe(text):
            for private in ('m'*32,'n'*32,'p'*32,'C'*43,'provider-SECRET','fixture@example.test'):
                text = text.replace(private,'[redacted]')
            return text
        for name in containers:
            print(name, safe(docker('logs', name)))
        if prometheus in containers:
            print(safe(str(request('http://' + ip + ':9090/api/v1/targets'))))
        raise
    finally:
        for name in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in volumes:
            subprocess.run(['docker', 'volume', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in networks:
            subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in images:
            subprocess.run(['docker', 'image', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
