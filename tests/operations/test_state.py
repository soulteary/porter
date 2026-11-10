import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operations', ROOT / 'tests/operations.py')
operations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operations)


def payload():
    return {'status': 'success', 'data': {'groups': [{'name': 'porter',
            'lastEvaluation': '2026-11-10T05:19:21.765704529Z',
            'rules': [{'name': name, 'health': 'ok', 'lastError': ''}
                      for name in ('PorterScrapeUnavailable', 'PorterReadinessFailed')]}]}}


class RuleEvaluation(unittest.TestCase):
    def test_server_evaluations_advance_without_host_wall_clock(self):
        before = payload()
        after = copy.deepcopy(before)
        after['data']['groups'][0]['lastEvaluation'] = '2026-11-10T05:19:26.123456789Z'
        first = operations.rule_evaluation_time(before)
        second = operations.rule_evaluation_time(after)
        self.assertIsNotNone(first)
        self.assertGreater(second, first)
        self.assertAlmostEqual(second - first, 4.357752, places=5)

    def test_errors_missing_rules_and_naive_timestamps_do_not_advance(self):
        for scenario in ('api error', 'rule error', 'missing rule', 'missing group', 'invalid timestamp', 'naive timestamp'):
            with self.subTest(scenario=scenario):
                value = payload()
                group = value['data']['groups'][0]
                if scenario == 'api error': value['status'] = 'error'
                elif scenario == 'rule error': group['rules'][0].update(health='err', lastError='query failed')
                elif scenario == 'missing rule': group['rules'].pop()
                elif scenario == 'missing group': group['name'] = 'other'
                elif scenario == 'invalid timestamp': group['lastEvaluation'] = 'invalid'
                else: group['lastEvaluation'] = '2026-11-10T05:19:21'
                self.assertIsNone(operations.rule_evaluation_time(value))


if __name__ == '__main__':
    unittest.main()
