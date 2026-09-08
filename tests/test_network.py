import xml.etree.ElementTree as ET
from pathlib import Path
import unittest
from test_desktop import reporter


class NetworkTests(unittest.TestCase):
    def score(self, event_time, anchor_time):
        return reporter._v16_3_network_match_score(
            image_name='powershell.exe', target_host='', target_ip='192.0.2.10',
            query_name='example.com', query_results='192.0.2.10;',
            event_time=event_time, anchor_time=anchor_time,
            focus_domain='example.com', focus_images=['powershell.exe'],
            ip_candidates=['192.0.2.10'])

    def test_dns_ip_and_time_correlation(self):
        self.assertEqual(self.score('2026-09-08T12:00:30+00:00', '2026-09-08T12:00:00+00:00'), 15)

    def test_missing_time_does_not_get_time_bonus(self):
        self.assertEqual(self.score('', '2026-09-08T12:00:00+00:00'), 12)

    def test_timezone_offsets_compare_actual_time(self):
        self.assertEqual(self.score('2026-09-08T05:00:30-07:00', '2026-09-08T12:00:00+00:00'), 15)

    def test_distant_event_has_no_time_bonus(self):
        self.assertEqual(self.score('2026-09-08T12:03:00+00:00', '2026-09-08T12:00:00+00:00'), 12)

    def test_baseline_enables_network_evidence(self):
        config = ET.parse(Path(__file__).resolve().parents[1] / 'config/sysmon-balanced.xml')
        for tag in ['ProcessCreate', 'NetworkConnect', 'DnsQuery']:
            node = config.find(f'EventFiltering/{tag}')
            self.assertIsNotNone(node)
            self.assertEqual(node.attrib['onmatch'], 'exclude')
            self.assertEqual(len(node), 0)

    def test_mixed_timezone_information_is_not_guessed(self):
        self.assertEqual(self.score('2026-09-08T12:00:30', '2026-09-08T12:00:00+00:00'), 12)

    def test_dns_results_validate_ipv4_and_support_ipv6(self):
        self.assertEqual(reporter._v16_2_extract_ipv4_candidates(
            'type: 5 alias.example.com;192.0.2.10;2001:db8::1;::ffff:192.0.2.10;999.1.2.3;'),
            ['192.0.2.10', '2001:db8::1'])

    def test_log_failure_is_preserved_as_evidence_gap(self):
        from unittest.mock import patch
        with patch.object(reporter, 'run_powershell', side_effect=RuntimeError('Access denied')):
            result = reporter.collect_event_log('Security', [4688], 1, 10)
        self.assertEqual(result['events'], [])
        self.assertIn('Access denied', result['error'])

    def test_event_cap_and_single_event_response(self):
        from unittest.mock import patch
        with patch.object(reporter, 'run_powershell', return_value='{"exists":true,"events":{"Id":22}}'):
            result = reporter.collect_event_log('Sysmon', [22], 1, 1)
        self.assertTrue(result['limit_reached'])

    def test_busy_sysmon_does_not_crowd_out_dns_and_network(self):
        from unittest.mock import patch
        def collect(log, ids, days, limit):
            return {'exists': True, 'limit_reached': True, 'events': [
                {'Id': ids[0], 'RecordId': ids[0], 'TimeCreated': '2026-09-08T04:37:20+00:00'}]}
        with patch.object(reporter, 'collect_event_log', side_effect=collect) as query:
            result = reporter.collect_sysmon_logs(3, 1)
        self.assertEqual({e['Id'] for e in result['events']}, {1, 3, 22})
        self.assertEqual(query.call_count, 3)
        self.assertEqual([c['count'] for c in result['query_coverage']], [1, 1, 1])
        self.assertTrue(result['limit_reached'])

    def test_partial_sysmon_failure_keeps_other_groups(self):
        from unittest.mock import patch
        def collect(log, ids, days, limit):
            if ids == [22]:
                return {'exists': False, 'events': [], 'error': 'DNS query timed out'}
            return {'exists': True, 'events': [{'Id': ids[0]}]}
        with patch.object(reporter, 'collect_event_log', side_effect=collect):
            result = reporter.collect_sysmon_logs(3, 50)
        self.assertTrue(result['exists'])
        self.assertEqual(len(result['events']), 2)
        self.assertIn('DNS query timed out', result['error'])

    def test_expanded_ipv6_destination_matches_compressed_dns_result(self):
        score = reporter._v16_3_network_match_score(
            image_name='', target_host='', target_ip='2603:1036:308:2834:0:0:0:2',
            query_name='', query_results='', event_time='', anchor_time='',
            focus_domain='', focus_images=[], ip_candidates=['2603:1036:308:2834::2'])
        self.assertEqual(score, 5)
