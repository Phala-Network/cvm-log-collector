import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from collector import BoundaryError, Processor, Store, redact_pem, split_utf8, timestamp_ns
from credentials_only import sanitize_for_test


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / 'state.sqlite3')
        self.labels = {'job': 'cvm-runtime', 'cvm_uuid': '11111111-2222-4333-8444-555555555555', 'region': 'fixture'}
        self.processor = Processor(self.store, self.labels, str(self.root))

    def tearDown(self):
        self.store.db.close()
        self.temporary.cleanup()

    def entry(self, body, cursor='cursor1', **extra):
        return {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': '1793600000123456',
                'SYSLOG_TIMESTAMP': '2026-11-02T07:00:00.123456789Z',
                'CONTAINER_ID_FULL': 'container1', 'CONTAINER_NAME': 'fixture-service',
                'PRIORITY': '6', 'MESSAGE': body} | extra

    def packets(self):
        return [json.loads(row[0]) for row in self.store.db.execute('SELECT body FROM queue ORDER BY id')]

    def lines(self):
        return [value[1] for packet in self.packets() for stream in packet['streams'] for value in stream['values']]

    def test_opaque_payload_id_and_plain_base64_preserved(self):
        for index, body in enumerate(('unframed payload={"messages":["hello world"]} request_id=req123\t', 'aG9zdG5hbWUgbm9uIHNlY3JldCB1c2VyIHBheWxvYWQ=')):
            self.processor.journal(self.entry(body, 'opaque'+str(index)))
        self.assertEqual(self.lines(), ['unframed payload={"messages":["hello world"]} request_id=req123\t', 'aG9zdG5hbWUgbm9uIHNlY3JldCB1c2VyIHBheWxvYWQ='])

    def test_pem_context_survives_restart_isolates_stderr_and_is_not_raw_on_disk(self):
        self.processor.journal(self.entry('before -----BEGIN PRIVATE KEY-----', 'pem1'))
        self.processor.journal(self.entry('stdout key body FAKE_KEY_BODY_m42', 'pem2'))
        self.processor = Processor(self.store, self.labels, str(self.root))
        self.processor.journal(self.entry('stderr payload untouched', 'pem3', PRIORITY='3'))
        self.processor.journal(self.entry('more FAKE_KEY_BODY_AFTER_RESTART -----END PRIVATE KEY----- after payload', 'pem4'))
        self.processor.journal(self.entry('normal text after end', 'pem5'))
        self.assertEqual(self.lines(), ['before [REDACTED_PRIVATE_KEY]', '[REDACTED_PRIVATE_KEY]', 'stderr payload untouched', '[REDACTED_PRIVATE_KEY] after payload', 'normal text after end'])
        self.assertEqual(self.store.get('journal_pem'), {})
        for path in self.root.glob('state.sqlite3*'):
            self.assertNotIn(b'FAKE_KEY_BODY', path.read_bytes())

    def test_partial_secret_and_split_unicode_reassembled_before_redaction(self):
        body = ('x' * 16370 + ' api_key=FAKE_CROSS_CHUNK_SECRET_239 ' + '😀' * 18000 + ' payload=keep request_id=abcdef').encode()
        raw_chunks = [body[i:i+16384] for i in range(0, len(body), 16384)]
        for index, part in enumerate(raw_chunks):
            message = part.decode() if self.valid_utf8(part) else list(part)
            self.processor.journal(self.entry(message, 'partial'+str(index),
                CONTAINER_PARTIAL_ID='partial-id', CONTAINER_PARTIAL_ORDINAL=str(index+1),
                CONTAINER_PARTIAL_LAST=str(index == len(raw_chunks)-1).lower()))
        self.assertEqual(''.join(self.lines()), sanitize_for_test(body.decode()))
        self.assertNotIn('FAKE_CROSS_CHUNK_SECRET', ''.join(self.lines()))
        self.assertEqual(self.packets()[0]['streams'][0]['values'][0][0], str(timestamp_ns('2026-11-02T07:00:00.123456789Z')))

    @staticmethod
    def valid_utf8(value):
        try:
            value.decode()
            return True
        except UnicodeDecodeError:
            return False

    def test_incomplete_partial_does_not_advance_checkpoint(self):
        self.processor.journal(self.entry('plain before partial', 'before'))
        self.processor.journal(self.entry('raw partial secret', 'pending', CONTAINER_PARTIAL_ID='p1', CONTAINER_PARTIAL_ORDINAL='1', CONTAINER_PARTIAL_LAST='false'))
        self.processor.journal(self.entry('another stream line', 'interleaved', CONTAINER_ID_FULL='container2'))
        self.assertEqual(self.store.get('journal_cursor'), 'before')
        self.assertEqual(len(self.lines()), 2)
        for path in self.root.glob('state.sqlite3*'):
            self.assertNotIn(b'raw partial secret', path.read_bytes())
        for partial in self.processor.partials.values():
            partial['file'].close()

    def test_missing_ordinal_fails_without_checkpoint_or_output(self):
        with self.assertRaises(BoundaryError):
            self.processor.journal(self.entry('unknown partial', CONTAINER_PARTIAL_ID='p1', CONTAINER_PARTIAL_ORDINAL='4', CONTAINER_PARTIAL_LAST='true'))
        self.assertEqual(self.lines(), [])
        self.assertIsNone(self.store.get('journal_cursor'))

    def test_interleaved_partial_pem_and_restart_replays_from_safe_anchor(self):
        self.processor.journal(self.entry('safe anchor', 'anchor'))
        first=self.entry('long prefix ', 'part1', CONTAINER_PARTIAL_ID='p1', CONTAINER_PARTIAL_ORDINAL='1', CONTAINER_PARTIAL_LAST='false')
        pem_begin=self.entry('-----BEGIN PRIVATE KEY-----', 'pem1', CONTAINER_ID_FULL='container2')
        pem_body=self.entry('FAKE_INTERLEAVED_PEM_BODY', 'pem2', CONTAINER_ID_FULL='container2')
        self.processor.journal(first)
        self.processor.journal(pem_begin)
        self.processor.journal(pem_body)
        # Emulate local ACKs before process crash. The pending raw partial
        # pins checkpoint+PEM snapshot to the safe replay anchor.
        for row_id, in self.store.db.execute('SELECT id FROM queue').fetchall():
            self.store.ack(row_id)
        self.assertEqual(self.store.get('journal_cursor'), 'anchor')
        for partial in self.processor.partials.values():partial['file'].close()
        self.processor=Processor(self.store,self.labels,str(self.root))
        for value in (first,pem_begin,pem_body):self.processor.journal(value)
        self.processor.journal(self.entry('long suffix', 'part2', CONTAINER_PARTIAL_ID='p1', CONTAINER_PARTIAL_ORDINAL='2', CONTAINER_PARTIAL_LAST='true'))
        self.processor.journal(self.entry('FAKE_AFTER_REPLAY -----END PRIVATE KEY----- tail', 'pem3', CONTAINER_ID_FULL='container2'))
        self.assertNotIn('FAKE_', ''.join(self.lines()))
        self.assertIn('long prefix long suffix',self.lines())
        self.assertEqual(self.store.get('journal_cursor'),'pem3')
        self.assertFalse(self.store.get('journal_pem'))

    def test_32_mib_ascii_boundary_is_split_and_all_queue_requests_bounded(self):
        body='X'*(32*1024*1024)
        self.processor.journal(self.entry(body))
        self.assertEqual(sum(len(line) for line in self.lines()),len(body))
        ids, packet=self.store.batch()
        self.assertGreater(len(self.lines()),100)
        self.assertLess(len(packet.encode()),900*1024)
        self.assertGreater(len(ids),1)

    def test_fragments_identical_chunks_unique_time_and_exact_body(self):
        body = 'L' * (240*1024*3) + '終わり'
        self.processor.journal(self.entry(body))
        stream = self.packets()[0]['streams'][0]
        values = [v for packet in self.packets() for s in packet['streams'] for v in s['values']]
        self.assertEqual(''.join(v[1] for v in values), body)
        self.assertEqual(values[0][1], values[1][1])
        self.assertEqual([int(v[0]) for v in values], list(range(int(values[0][0]), int(values[0][0])+len(values))))
        self.assertTrue(all(set(v[2]) == {'fragment_id','fragment_index','fragment_count','original_timestamp'} for v in values))
        self.assertTrue(all(len(v[1].encode()) <= 240*1024 for v in values))
        self.assertEqual(stream['stream']['stream'], 'stdout')

    def test_two_mib_control_escaping_local_requests_are_bounded(self):
        body = ('\x01\x02\x03\x04\x05\x06\x07\x08\t\r' * 210000) + 'request_id=keep payload=full'
        self.processor.journal(self.entry(body))
        self.assertEqual(''.join(self.lines()), body)
        self.assertTrue(all(len(row[0].encode()) < 900*1024 for row in self.store.db.execute('SELECT body FROM queue')))
        self.assertEqual(self.store.get('journal_cursor'), 'cursor1')

    def test_kernel_sequence_cursor_timestamp_and_pem_state(self):
        self.processor.kernel(b'6,10,123456,c,extra;kernel body payload=keep request_id=k10\n', 'boot1', 1_000_000_000)
        self.processor.kernel(b'6,10,123456,c;duplicate not emitted\n', 'boot1', 1_000_000_000)
        self.processor.kernel(b'3,12,123466,-;-----BEGIN RSA PRIVATE KEY-----\n', 'boot1', 1_000_000_000)
        self.processor = Processor(self.store, self.labels, str(self.root))
        self.processor.kernel(b'3,13,123467,-;FAKE_KERNEL_PRIVATE_BODY\n', 'boot1', 1_000_000_000)
        self.processor.kernel(b'3,14,123468,-;-----END RSA PRIVATE KEY----- retained tail\n', 'boot1', 1_000_000_000)
        self.assertEqual(self.lines(), ['kernel body payload=keep request_id=k10', '[REDACTED_PRIVATE_KEY]', '[REDACTED_PRIVATE_KEY]', '[REDACTED_PRIVATE_KEY] retained tail'])
        self.assertEqual(self.packets()[0]['streams'][0]['values'][0][0], '1123456000')
        self.assertEqual(self.packets()[0]['streams'][0]['stream']['stream'], 'kernel')
        self.assertFalse(self.store.get('kernel_checkpoint')['pem'])


if __name__ == '__main__':
    unittest.main()
