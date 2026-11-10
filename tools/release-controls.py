#!/usr/bin/env python3
"""Plan/check additive release controls; never approve a deployment or create a tag."""
import argparse
import json
import pathlib
import re
import subprocess


class Refused(Exception):
    pass


def api(method, route, body=None, missing=False):
    args = ['gh', 'api', '--method', method, route]
    if body is not None:
        args += ['--input', '-']
    result = subprocess.run(args, input=json.dumps(body) if body is not None else None,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        try:
            absent = str(json.loads(result.stdout).get('status')) == '404'
        except (ValueError, AttributeError):
            absent = False
        if missing and absent:
            return None
        raise Refused('GitHub API request failed; inspect repository access privately')
    return json.loads(result.stdout) if result.stdout.strip() else None


def desired(policy):
    if not isinstance(policy, dict):
        raise Refused('invalid release-control policy')
    repository = policy.get('repository', '')
    reviewers = policy.get('reviewers', [])
    if not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 6:
        raise Refused('invalid release-control policy')
    for reviewer in reviewers:
        if not isinstance(reviewer, dict) or not isinstance(reviewer.get('login'), str) or not re.fullmatch(r'[A-Za-z0-9-]+', reviewer.get('login', '')) or type(reviewer.get('id')) is not int or reviewer['id'] <= 0:
            raise Refused('invalid reviewer identity')
    if len({item['id'] for item in reviewers}) != len(reviewers) or type(policy.get('prevent_self_review')) is not bool:
        raise Refused('invalid reviewer policy')
    environment = {'reviewers': [{'type': 'User', 'id': item['id']} for item in reviewers],
                   'prevent_self_review': policy['prevent_self_review'],
                   'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
    ruleset = {'name': 'porter-release-tags', 'target': 'tag', 'enforcement': 'active',
               'conditions': {'ref_name': {'include': ['refs/tags/v*'], 'exclude': []}},
               'bypass_actors': [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}],
               'rules': [{'type': kind} for kind in ('creation', 'update', 'deletion')]}
    return repository, environment, ruleset


def plan(policy, request=api):
    repository, environment, ruleset = desired(policy)
    root = 'repos/' + repository
    for reviewer in policy['reviewers']:
        identity = request('GET', 'users/' + reviewer['login'])
        if identity['id'] != reviewer['id']:
            raise Refused('reviewer login does not match the pinned identity')
    current = request('GET', root + '/environments/release', missing=True)
    changes = []
    if current is None:
        changes.append(('PUT', root + '/environments/release', environment))
        branches = []
    else:
        approvals = [rule for rule in current.get('protection_rules', []) if rule.get('type') == 'required_reviewers']
        approved = {item['reviewer']['id'] for rule in approvals for item in rule.get('reviewers', []) if item['type'] == 'User'}
        if any(item['type'] != 'User' for rule in approvals for item in rule.get('reviewers', [])):
            raise Refused('existing release reviewers include an unplanned team')
        if approved != {item['id'] for item in policy['reviewers']} or len(approvals) != 1 or approvals[0].get('prevent_self_review', False) != environment['prevent_self_review'] or current.get('deployment_branch_policy') != environment['deployment_branch_policy']:
            raise Refused('existing release environment differs; refusing to overwrite it')
        branch_page = request('GET', root + '/environments/release/deployment-branch-policies?per_page=100')
        branches = branch_page['branch_policies']
        if branch_page.get('total_count', len(branches)) > len(branches) or len(branches) >= 100:
            raise Refused('environment policy inventory exceeds the reviewed page bound')
        if any(item.get('name') != 'v*' or item.get('type') != 'tag' for item in branches):
            raise Refused('existing environment permits other refs; review it manually')
    if not branches:
        changes.append(('POST', root + '/environments/release/deployment-branch-policies', {'name': 'v*', 'type': 'tag'}))
    existing = request('GET', root + '/rulesets?per_page=100')
    if len(existing) >= 100:
        raise Refused('ruleset inventory exceeds the reviewed page bound')
    matches = [item for item in existing if item['name'] == ruleset['name']]
    if len(matches) > 1:
        raise Refused('ambiguous managed ruleset')
    if matches:
        current_rule = request('GET', root + '/rulesets/' + str(matches[0]['id']))
        current_rule = dict(current_rule)
        current_rule['rules'] = sorted(current_rule.get('rules', []), key=lambda rule: rule['type'])
        expected_rule = dict(ruleset)
        expected_rule['rules'] = sorted(ruleset['rules'], key=lambda rule: rule['type'])
        if any(current_rule.get(key) != value for key, value in expected_rule.items()):
            raise Refused('existing managed tag rules differ; refusing to overwrite them')
    else:
        changes.append(('POST', root + '/rulesets', ruleset))
    return changes


def execute(policy, apply=False, request=api):
    changes = plan(policy, request)
    if apply:
        # All reads and conflict checks complete before the first mutation.
        for method, route, body in changes:
            request(method, route, body)
        if plan(policy, request):
            raise Refused('release controls did not converge; inspect partial changes')
    return {'ok': not changes or apply, 'applied': bool(apply and changes),
            'planned_requests': [{'method': method, 'route': route, 'body': body} for method, route, body in changes]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-repository')
    parser.add_argument('--policy', type=pathlib.Path, default=pathlib.Path('examples/release/controls.json'))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        policy = json.loads(args.policy.read_text())
        repository, _, _ = desired(policy)
        if args.expected_repository and args.expected_repository.lower() != repository.lower():
            raise Refused('policy repository does not match the workflow repository')
        result = execute(policy, args.apply)
        print(json.dumps(result, indent=2))
        if args.check and not result['ok']:
            raise SystemExit(1)
    except (Refused, ValueError, OSError) as error:
        parser.exit(1, 'release controls refused: ' + (str(error) if isinstance(error, Refused) else 'invalid policy or file access') + '\n')


if __name__ == '__main__':
    main()
