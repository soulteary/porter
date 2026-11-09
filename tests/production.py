#!/usr/bin/env python3
"""Opt-in Docker acceptance against a pinned, real baseline. Uses no live providers."""
import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = "bdf69d4600cba5cf55b8df65247e7f4ea1f5899d"  # Merged PR #2.
PROXY_KEY, MANAGEMENT_KEY = "p" * 32, "m" * 32


def run(*args, capture=False):
    result = subprocess.run(args, cwd=ROOT, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None)
    return result.stdout.strip() if capture else None


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def request(port, path, *, management=False, token=None, method="GET", key=None):
    headers = {"Host": "porter.test", "Origin": "https://porter.test"}
    if management:
        headers["Authorization"] = "Bearer " + (MANAGEMENT_KEY if key is None else key)
    elif token:
        headers["Authorization"] = "Bearer " + PROXY_KEY
        headers["Cookie"] = "__Host-porter_session=" + token * 43
    req = urllib.request.Request("http://127.0.0.1:" + port + path,
                                 headers=headers, method=method)
    # No environment proxy or redirect following in the acceptance client.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = client.open(req, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, dict(response.headers), response.read()


def require_status(expected, *args, **kwargs):
    status, headers, body = request(*args, **kwargs)
    assert status == expected, (args, status, body[:100])
    return headers, body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=BASELINE)
    parser.add_argument("--candidate-context", type=pathlib.Path, default=ROOT,
                        help="production source tree to build (defaults to this checkout)")
    args = parser.parse_args()
    # Resolve to a commit before using it as an archive source.
    baseline = run("git", "rev-parse", "--verify", args.baseline + "^{commit}", capture=True)
    candidate_context = args.candidate_context.resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=candidate_context, text=True).strip()
    suffix = uuid.uuid4().hex[:12]
    current, previous, fixture = ["porter-acceptance-" + name + ":" + suffix
                                  for name in ("candidate", "baseline", "fixture")]
    volume, active = "porter-acceptance-" + suffix, []
    built = []

    def helper(command):
        docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", volume + ":/data", fixture, command)

    def start(image):
        container = docker("run", "-d", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges:true",
                           "-v", volume + ":/data", "-p", "127.0.0.1::8083",
                           "-p", "127.0.0.1::9093", image,
                           "serve", "-config", "/data/porter.json", capture=True)
        active.append(container)
        ports = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", container, capture=True))
        public = ports["8083/tcp"][0]["HostPort"]
        management = ports["9093/tcp"][0]["HostPort"]
        for _ in range(60):
            try:
                if request(management, "/readyz", management=True)[0] == 200:
                    return container, public, management
            except (OSError, urllib.error.URLError):
                pass
            if docker("inspect", "--format", "{{.State.Running}}", container, capture=True) != "true":
                raise AssertionError("production container exited during startup")
            time.sleep(0.2)
        raise AssertionError("production container did not become ready")

    def stop(container):
        docker("stop", "--time", "15", container)
        code = docker("inspect", "--format", "{{.State.ExitCode}}", container, capture=True)
        assert code == "0", "unclean shutdown: " + code
        logs = docker("logs", container, capture=True)
        for secret in ("FIXTURE_SECRET", "fixture@example.test", PROXY_KEY, MANAGEMENT_KEY, "L" * 43):
            assert secret not in logs, "secret in production logs"
        docker("rm", container)
        active.remove(container)

    def sessions(public, live):
        for token in ("L", "C", "R", "E"):
            headers, _ = require_status(200 if token in live else 401, public, "/identity", token=token)
            if token in live:
                assert headers.get("X-Porter-User-Id") == "u1" or headers.get("X-Porter-User-ID") == "u1"

    try:
        with tempfile.TemporaryDirectory(prefix="porter-baseline-") as directory:
            archive = pathlib.Path(directory) / "baseline.tar"
            run("git", "archive", "--format=tar", "--output=" + str(archive), baseline)
            run("tar", "-xf", str(archive), "-C", directory)
            archive.unlink()
            docker("build", "-t", previous, directory)
            built.append(previous)
            shutil.copytree(ROOT / "tests" / "fixture", pathlib.Path(directory) / "tests" / "fixture")
            shutil.copyfile(ROOT / "tests" / "fixture.Dockerfile", pathlib.Path(directory) / "tests" / "fixture.Dockerfile")
            with (pathlib.Path(directory) / ".dockerignore").open("a") as ignore:
                ignore.write("\n!tests/\n!tests/fixture.Dockerfile\n!tests/fixture/\n!tests/fixture/**\n")
            docker("build", "-f", str(pathlib.Path(directory) / "tests" / "fixture.Dockerfile"), "-t", fixture, directory)
            built.append(fixture)
        built_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        docker("build", "-t", current, "--build-arg", "VERSION=acceptance",
               "--build-arg", "COMMIT=" + commit, "--build-arg", "BUILD_DATE=" + built_date, str(candidate_context))
        built.append(current)
        user = docker("image", "inspect", "--format", "{{.Config.User}}", current, capture=True)
        assert user and user.split(":")[0] not in ("0", "root"), "production image must default to non-root"
        version = json.loads(docker("run", "--rm", "--network", "none", "--read-only", current, "version", "--json", capture=True))
        assert (version["version"], version["commit"], version["build_date"]) == ("acceptance", commit, built_date)
        docker("volume", "create", volume)
        helper("seed")
        container, public, management = start(previous)
        sessions(public, {"L", "C"})
        stop(container)
        container, public, management = start(current)
        sessions(public, {"L", "C"})
        for path in ("/metrics", "/readyz", "/version"):
            require_status(404, public, path)
            require_status(401, management, path, management=True, key=PROXY_KEY)
            require_status(200, management, path, management=True)
        require_status(503, public, "/auth", token="L")  # No Stargate configured: fail closed.
        require_status(200, public, "/login/github", method="POST")  # No external request.
        require_status(303, public, "/logout", method="POST", token="L")
        sessions(public, {"C"})
        stop(container)
        container, public, management = start(current)
        sessions(public, {"C"})
        stop(container)
        container, public, management = start(previous)
        sessions(public, {"C"})
        stop(container)
        helper("verify")  # Old implementation reads records and enforces one-use transactions.
        helper("change-binding")
        container, public, management = start(current)
        sessions(public, set())
        stop(container)
        helper("restore-binding")
        container, public, management = start(previous)
        sessions(public, set())  # Restoring an old mapping must not revive revoked families.
        stop(container)
        helper("unsafe-audit")
        failed = subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                                 "-v", volume + ":/data", current, "serve", "-config", "/data/porter.json"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        assert failed.returncode == 1 and "audit file must be" in failed.stdout, "unsafe journal did not fail startup"
        for secret in ("FIXTURE_SECRET", "fixture@example.test", PROXY_KEY, MANAGEMENT_KEY):
            assert secret not in failed.stdout, "startup error disclosed secrets"
        print("PASS: production image, upgrade, restart, rollback, expiry, revocation, binding reconciliation and pending transactions")
    finally:
        for container in active:
            subprocess.run(["docker", "rm", "-f", container], check=False)
        subprocess.run(["docker", "volume", "rm", volume], check=False)
        for image in built:
            subprocess.run(["docker", "image", "rm", image], check=False)


if __name__ == "__main__":
    main()
