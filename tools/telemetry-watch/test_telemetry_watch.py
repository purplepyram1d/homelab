import contextlib
import json
from pathlib import Path
import tempfile
import unittest

import telemetry_watch as watch

NOW = 1792834800.0


def event(host='SRV01', sample=NOW, status='ok'):
    return dict(agent=dict(id='003' if host=='SRV01' else '001', name=host),
                manager=dict(name='siem01'), rule=dict(id='100892' if status=='ok' else '100893'),
                id='native-' + str(sample), timestamp=watch.utc(sample + 1), location=watch.LOCATION,
                data=dict(homelab_health=dict(kind='sysmon', host=host, utc=watch.utc(sample), status=status)))


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='telemetry-watch-test-', dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'alerts.json'
        self.state = self.root / 'state.sqlite3'
        self.output = self.root / 'events.jsonl'

    def write(self, *events):
        self.source.write_text(''.join(json.dumps(e)+'\n' for e in events), encoding='utf-8')

    def run_watch(self, now=NOW):
        return watch.run(self.source, self.state, self.output, now)

    def output_events(self):
        return [json.loads(s)['homelab_watch'] for s in self.output.read_text().splitlines()] if self.output.exists() else []

    def test_fresh_baseline_no_alert(self):
        self.write(event(), event('DC01'))
        result = self.run_watch()
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(result['emitted'], 0)

    def test_stale_boundary_and_no_repeat(self):
        self.write(event(), event('DC01'))
        self.run_watch()
        self.assertEqual(self.run_watch(NOW+900)['emitted'], 0)
        self.assertEqual(self.run_watch(NOW+901)['emitted'], 2)
        self.assertEqual(self.run_watch(NOW+5000)['emitted'], 0)

    def test_recovery_once_and_new_outage(self):
        self.write(event(), event('DC01'))
        self.run_watch(NOW+901)
        self.write(event(sample=NOW+950), event('DC01', NOW+950))
        self.assertEqual(self.run_watch(NOW+951)['emitted'], 2)
        self.assertEqual(self.run_watch(NOW+952)['emitted'], 0)
        self.assertEqual(self.run_watch(NOW+1851)['emitted'], 2)
        self.assertEqual([e['status'] for e in self.output_events()].count('recovered'), 2)

    def test_never_seen_startup_grace_persists_across_invocations(self):
        self.write()
        self.assertEqual(self.run_watch()['emitted'], 0)
        self.assertEqual(self.run_watch(NOW+900)['emitted'], 0)
        self.assertEqual(self.run_watch(NOW+901)['emitted'], 2)

    def test_late_backlog_does_not_make_fresh(self):
        old = event(sample=NOW-2000)
        old['timestamp'] = watch.utc(NOW)
        self.write(old, event('DC01'))
        result = self.run_watch()
        self.assertEqual(result['hosts']['SRV01']['arrival'], 'stale')
        self.assertEqual(result['hosts']['DC01']['arrival'], 'fresh')

    def test_replayed_old_event_cannot_extend_deadline(self):
        self.write(event(), event('DC01'))
        self.run_watch()
        self.assertEqual(self.run_watch(NOW+901)['hosts']['SRV01']['arrival'], 'stale')

    def test_fail_report_is_producer_alive(self):
        self.write(event(status='fail'), event('DC01'))
        result = self.run_watch()
        self.assertEqual(result['hosts']['SRV01']['arrival'], 'fresh')
        self.assertEqual(result['hosts']['SRV01']['sample_status'], 'fail')
        self.assertFalse(self.output.exists())

    def test_invalid_identity_and_clock_controls(self):
        variants = [lambda e:e['agent'].update(name='DC01'),
                    lambda e:e['data']['homelab_health'].update(host='DC01'),
                    lambda e:e.update(location='wrong-path'),
                    lambda e:e['manager'].update(name='other'),
                    lambda e:e['data']['homelab_health'].update(utc=watch.utc(NOW+61)),
                    lambda e:e.update(timestamp=watch.utc(NOW+61)),
                    lambda e:e['data']['homelab_health'].update(utc='2026-10-24T09:00:00'),
                    lambda e:e['data']['homelab_health'].update(status='fail')]
        for mutation in variants:
            item=event();mutation(item)
            with self.subTest(item=item):
                with self.assertRaises((ValueError,KeyError)):
                    watch.candidate(item,NOW)

    def test_nonhealth_and_unexpected_agent_ignored(self):
        item=event();item['rule']['id']='100894'
        self.assertIsNone(watch.candidate(item,NOW))
        item=event();item['agent']['id']='999'
        self.assertIsNone(watch.candidate(item,NOW))

    def test_double_slash_location_is_supported(self):
        item=event();item['location']=watch.LOCATION.replace('\\','\\\\')
        self.assertEqual(watch.candidate(item,NOW)['host'],'SRV01')

    def test_partial_line_not_consumed(self):
        self.write(event('DC01'))
        with self.source.open('a') as f:f.write(json.dumps(event()))
        result=self.run_watch()
        self.assertEqual(result['hosts']['SRV01']['arrival'],'starting')
        with self.source.open('a') as f:f.write('\n')
        self.assertEqual(self.run_watch()['hosts']['SRV01']['arrival'],'fresh')

    def test_source_missing_then_recovery_visible(self):
        self.assertEqual(self.run_watch()['result'],'REVIEW')
        self.assertEqual(self.run_watch()['emitted'],0)
        self.write(event(),event('DC01'))
        self.assertEqual(self.run_watch()['emitted'],1)
        self.assertEqual([x['status'] for x in self.output_events()],['observer_error','observer_recovered'])

    def test_clock_rollback_cannot_falsely_recover(self):
        self.write(event(),event('DC01'))
        self.run_watch(NOW+901)
        result=self.run_watch(NOW)
        self.assertEqual(result['hosts']['SRV01']['arrival'],'stale')
        self.assertEqual(result['emitted'],1)
        self.assertEqual(self.run_watch(NOW+1)['emitted'],0)

    def test_malformed_input_reports_observer_problem(self):
        self.source.write_text('not-json\n')
        result=self.run_watch()
        self.assertEqual(result['scan']['malformed'],1)
        self.assertEqual(result['result'],'REVIEW')
        self.assertEqual(self.output_events()[0]['status'],'observer_error')

    def test_private_state_does_not_store_full_source(self):
        item=event();item['full_log']='DO_NOT_STORE_RAW_COMMANDLINE'
        self.write(item,event('DC01'))
        self.run_watch()
        self.assertNotIn(b'DO_NOT_STORE_RAW_COMMANDLINE',self.state.read_bytes())

    def test_outbox_survives_output_failure(self):
        self.write(event(sample=NOW-2000),event('DC01'))
        with self.assertRaises(OSError):watch.run(self.source,self.state,self.root/'missing'/'out.jsonl',NOW)
        self.assertEqual(self.run_watch()['emitted'],1)
        self.assertEqual(self.run_watch()['emitted'],0)

    def test_bounded_tail_finds_latest_report(self):
        with self.source.open('wb') as f:
            f.write(b'x'*(watch.MAX_BYTES+10)+b'\n')
            f.write((json.dumps(event())+'\n'+json.dumps(event('DC01'))+'\n').encode())
        result=self.run_watch()
        self.assertTrue(result['scan']['tail_limited'])
        self.assertEqual(result['hosts']['SRV01']['arrival'],'fresh')
        self.assertLessEqual(result['scan']['bytes_read'],watch.MAX_BYTES)

    def test_rotation_keeps_last_seen_and_does_not_refresh(self):
        self.write(event(),event('DC01'))
        self.run_watch()
        self.source.rename(self.root/'old-alerts.json')
        self.write()
        self.assertEqual(self.run_watch(NOW+901)['hosts']['SRV01']['arrival'],'stale')

    def test_clock_error_is_review_even_when_last_mode_fresh(self):
        self.write(event(),event('DC01'))
        self.run_watch(NOW+300)
        self.assertEqual(self.run_watch(NOW)['result'],'REVIEW')

    def test_older_sample_cannot_replace_newer_sample(self):
        self.write(event(),event('DC01'))
        self.run_watch()
        self.write(event(sample=NOW-100),event('DC01',NOW-100))
        self.assertEqual(self.run_watch(NOW+1)['hosts']['SRV01']['last_sample_utc'],watch.utc(NOW))

    @unittest.skipUnless(hasattr(__import__('os'),'O_NOFOLLOW'),'Linux no-follow control')
    def test_source_symlink_rejected(self):
        target=self.root/'real';target.write_text('')
        self.source.symlink_to(target)
        self.assertEqual(self.run_watch()['result'],'REVIEW')


if __name__=='__main__':unittest.main()
