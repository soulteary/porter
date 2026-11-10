import copy
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('contracts', pathlib.Path(__file__).resolve().parents[1] / 'contracts.py')
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


class Assertions(unittest.TestCase):
    def test_full_header_inventory_rejects_leaks_even_when_values_are_empty(self):
        for code in (200, 401, 403, 503):
            result = {'status': code, 'headers': {}, 'header_counts': {'content-type': 1}}
            if code == 200:
                result['headers'] = {'X-Auth-User': 'porter-fixture-user', 'X-Forwarded-User': 'porter-fixture-user', 'X-Auth-Role': 'user', 'X-Auth-Scopes': 'read'}
                result['header_counts'].update({name.lower(): 1 for name in result['headers']})
            contracts.validate_auth_response(result, {code})
            leaked = ('set-cookie', 'authorization', 'x-stargate-header-auth', 'x-user-mail', 'x-porter-user-id', 'x-debug-secret')
            if code != 200:
                leaked += tuple(contracts.AUTH_HEADERS)
            for name in leaked:
                with self.subTest(code=code, name=name):
                    bad = copy.deepcopy(result)
                    bad['header_counts'][name] = 1
                    with self.assertRaises(AssertionError):
                        contracts.validate_auth_response(bad, {code})
            if code == 200:
                bad = copy.deepcopy(result)
                bad['header_counts']['x-auth-user'] = 2
                with self.assertRaises(AssertionError):
                    contracts.validate_auth_response(bad, {code})


if __name__ == '__main__':
    unittest.main()
