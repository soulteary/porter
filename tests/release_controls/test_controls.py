import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('controls', ROOT / 'tools/release-controls.py')
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
POLICY = {'repository': 'owner/porter', 'reviewers': [{'login': 'maintainer', 'id': 1}], 'prevent_self_review': False}


class Server:
    def __init__(self):
        self.env, self.branches, self.rules = None, [], []
        self.writes = []

    def __call__(self, method, route, body=None, missing=False):
        if method != 'GET':
            self.writes.append((method, route, copy.deepcopy(body)))
            if method == 'PUT':
                self.env = {'protection_rules': [{'type': 'required_reviewers', 'prevent_self_review': body['prevent_self_review'], 'reviewers': [{'type': 'User', 'reviewer': {'id': item['id']}} for item in body['reviewers']]}], 'deployment_branch_policy': body['deployment_branch_policy']}
            elif 'deployment-branch-policies' in route:
                self.branches.append(body)
            else:
                self.rules.append(dict(body, id=10))
            return {}
        if route.startswith('users/'):
            return {'id': 1}
        if 'deployment-branch-policies' in route:
            return {'branch_policies': self.branches}
        if '/rulesets/' in route:
            return self.rules[0]
        if '/rulesets?' in route:
            return self.rules
        return self.env


class Controls(unittest.TestCase):
    def test_plan_is_read_only_and_apply_is_idempotent(self):
        server = Server()
        self.assertFalse(controls.execute(POLICY, request=server)['ok'])
        self.assertEqual(server.writes, [])
        controls.execute(POLICY, True, server)
        self.assertEqual(len(server.writes), 3)
        self.assertEqual(server.branches, [{'name': 'v*', 'type': 'tag'}])
        self.assertEqual({rule['type'] for rule in server.rules[0]['rules']}, {'creation', 'update', 'deletion'})
        controls.execute(POLICY, True, server)
        self.assertEqual(len(server.writes), 3)

    def test_conflicts_are_rejected_before_any_mutation(self):
        for scenario in ('reviewer', 'branch', 'ruleset', 'identity'):
            with self.subTest(scenario=scenario):
                server = Server()
                controls.execute(POLICY, True, server)
                server.writes.clear()
                if scenario == 'reviewer': server.env['protection_rules'][0]['reviewers'][0]['reviewer']['id'] = 9
                elif scenario == 'branch': server.branches.append({'name': 'main', 'type': 'branch'})
                elif scenario == 'ruleset': server.rules[0]['enforcement'] = 'disabled'
                policy = copy.deepcopy(POLICY)
                if scenario == 'identity': policy['reviewers'][0]['id'] = 9
                with self.assertRaises(controls.Refused): controls.execute(policy, True, server)
                self.assertEqual(server.writes, [])


if __name__ == '__main__':
    unittest.main()
