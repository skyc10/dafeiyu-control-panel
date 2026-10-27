import concurrent.futures
import time
import unittest
from unittest.mock import patch
import server

RUNNING = {name: {"state": "running", "running": True, "exitCode": None} for name in server.CONTAINERS}

class StatusTests(unittest.TestCase):
    def status(self, snapshot, containers=None, daemon=None):
        with patch.object(server, 'docker_daemon', return_value=daemon if daemon is not None else {"available": True}), patch.object(server, 'container_states', return_value=containers or RUNNING), patch.object(server, 'http_probe', return_value={"reachable": True, "status": 200}), patch.object(server, 'port_open', return_value=True), patch.object(server, 'bridge_snapshot', return_value=snapshot), patch.object(server, 'plugins_status', return_value=[]):
            return server.build_status()

    def test_auth_failure_is_not_ready_and_does_not_leak_activity(self):
        value = self.status({"_reporting": True, "dshReady": False, "dsh": {"errorKind": "authentication_failed", "httpStatus": 401}, "snowluma": {"connected": True, "accountOnline": True}, "activity": ["private-message"]})
        self.assertEqual(value['overall']['state'], 'degraded')
        self.assertFalse(value['services']['bridge']['ready'])
        self.assertEqual(value['services']['bridge']['errorKind'], 'authentication_failed')
        self.assertNotIn('private-message', str(value))
        self.assertEqual(value['qq']['status'], 'online')

    def test_event_stream_disconnect_overrides_http_readiness(self):
        value = self.status({"dshReady": True, "dsh": {"eventStreamConnected": False, "errorKind": "event_stream_disconnected"}})
        self.assertFalse(value['services']['bridge']['ready'])

    def test_online_and_unknown_are_distinct(self):
        value = self.status({"dshReady": True, "dsh": {"eventStreamConnected": True}, "snowluma": {"connected": True, "accountOnline": True}})
        self.assertEqual(value['overall']['state'], 'ready')
        value = self.status({"_reporting": False, "_probeError": "console_authentication_failed"})
        self.assertIsNone(value['services']['bridge']['dshReady'])
        self.assertEqual(value['qq']['status'], 'unknown')

    def test_stopped_and_docker_unavailable(self):
        stopped = {name: {"state": "exited", "running": False} for name in server.CONTAINERS}
        self.assertEqual(self.status({}, stopped)['overall']['state'], 'stopped')
        with patch.object(server, 'docker_daemon', return_value={"available": False}):
            states = server.container_states()
        self.assertTrue(all(v['state'] == 'unknown' for v in states.values()))

    def test_unavailable_docker_never_claims_containers_stopped(self):
        value = self.status({}, daemon={"available": False})
        self.assertEqual(value['overall']['state'], 'unknown')

    def test_concurrent_status_requests_share_one_build(self):
        server._STATUS_CACHE.update(at=0, value=None)
        def build():
            time.sleep(.05)
            return {"time": "same-snapshot"}
        with patch.object(server, 'build_status', side_effect=build) as mocked:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                values = list(pool.map(lambda _: server.cached_status(), range(5)))
        self.assertEqual(mocked.call_count, 1)
        self.assertTrue(all(v == values[0] for v in values))

    def test_explicit_console_token_has_priority(self):
        with patch.object(server, 'read_container_text', side_effect=['{"consoleToken":"explicit"}']) as mocked:
            self.assertEqual(server.read_bridge_token()[0], 'explicit')
            self.assertEqual(mocked.call_count, 1)

    def test_start_checks_daemon_before_containers(self):
        manager = server.JobManager()
        order = []
        with patch.object(manager, '_ensure_daemon', side_effect=lambda _: order.append('daemon') or True), patch.object(manager, '_ensure_containers', side_effect=lambda _: order.append('containers') or False):
            manager._action_start('test')
        self.assertEqual(order, ['daemon', 'containers'])

    def test_duplicate_job_reused_and_conflicting_action_rejected(self):
        manager = server.JobManager()
        with patch.object(server.threading.Thread, 'start'):
            first, created, _ = manager.submit('start')
            same, created_again, _ = manager.submit('start')
            conflict, _, error = manager.submit('stop_all')
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first['id'], same['id'])
        self.assertIsNone(conflict)
        self.assertIsNotNone(error)

if __name__ == '__main__':
    unittest.main()
