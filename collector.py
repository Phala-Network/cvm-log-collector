"""CVM journal/kmsg reader. No Docker API or remote credential access.

Raw partials live only in bounded anonymous tmpfs spools. SQLite contains only
sanitized output, checkpoint identities and boolean PEM context. A local Alloy
204 is an in-memory handoff, not durable remote acceptance.
"""
from __future__ import annotations

import calendar
import copy
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from credentials_only import POLICY_VERSION, sanitize_for_test

VERSION = '0.1.0'
CHUNK_BYTES = 240 * 1024
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_PENDING_BYTES = 64 * 1024 * 1024
MAX_PARTIAL_STREAMS = 128
PEM_BEGIN = re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----')
PEM_END = re.compile(r'-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----')
JOURNAL_FIELDS = ','.join(('MESSAGE', '__CURSOR', '__REALTIME_TIMESTAMP',
    'SYSLOG_TIMESTAMP', 'CONTAINER_ID_FULL', 'CONTAINER_NAME', 'PRIORITY',
    'CONTAINER_PARTIAL_ID', 'CONTAINER_PARTIAL_ORDINAL', 'CONTAINER_PARTIAL_LAST'))


class BoundaryError(RuntimeError):
    """Fail closed without printing input or advancing the source checkpoint."""


def timestamp_ns(value: str) -> int:
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)', value)
    if not match:
        raise BoundaryError('invalid_source_timestamp')
    base = dt.datetime.fromisoformat(match[1] + ('+00:00' if match[3] == 'Z' else match[3]))
    seconds = calendar.timegm(base.astimezone(dt.timezone.utc).timetuple())
    return seconds * 1_000_000_000 + int((match[2] or '').ljust(9, '0'))


def split_utf8(text: str, limit: int = CHUNK_BYTES) -> list[str]:
    data = text.encode('utf-8')
    if not data:
        return ['']
    result = []
    start = 0
    while start < len(data):
        end = min(start + limit, len(data))
        while end < len(data) and data[end] & 0xC0 == 0x80:
            end -= 1
        if end == start:
            raise BoundaryError('invalid_chunk_budget')
        result.append(data[start:end].decode('utf-8'))
        start = end
    return result


def split_transport(text: str) -> list[str]:
    """Respect both UTF-8 body bytes and worst-case JSON escaping overhead."""
    pending = split_utf8(text)
    result = []
    while pending:
        chunk = pending.pop(0)
        if len(json.dumps(chunk, ensure_ascii=False).encode('utf-8')) <= 512*1024:
            result.append(chunk)
            continue
        halves = split_utf8(chunk, max(4, len(chunk.encode('utf-8')) // 2))
        pending[0:0] = halves
    return result


def redact_pem(text: str, opened: bool) -> tuple[str, bool]:
    """Only a recognized PRIVATE KEY marker enters persistent PEM context.

    Every subsequent entry in that same source stream remains masked until an
    explicit END marker. Time, max-lines and restart never clear this state.
    """
    result = []
    position = 0
    while position < len(text) or opened:
        if opened:
            end = PEM_END.search(text, position)
            result.append('[REDACTED_PRIVATE_KEY]')
            if end is None:
                return ''.join(result), True
            position = end.end()
            opened = False
        else:
            begin = PEM_BEGIN.search(text, position)
            if begin is None:
                result.append(sanitize_for_test(text[position:]))
                break
            result.append(sanitize_for_test(text[position:begin.start()]))
            opened = True
            position = begin.end()
    return ''.join(result), opened


class Store:
    def __init__(self, path: Path, queue_bytes: int = 64 * 1024 * 1024):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.lock = threading.RLock()
        self.queue_limit = queue_bytes
        with self.db:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY, event_id TEXT UNIQUE, body TEXT NOT NULL, bytes INTEGER NOT NULL)')

    def get(self, key, default=None):
        with self.lock:
            row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value, separators=(',', ':'))))

    def usage(self):
        with self.lock:
            return self.db.execute('SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM queue').fetchone()

    def enqueue(self, event_id, packet, checkpoint=None, pem=None, kernel=None, stop=None):
        # Checkpoint/state and every fragment of one logical event commit in a
        # single transaction, but each queued/local HTTP request is bounded.
        fragments = []
        for stream in packet['streams']:
            for value in stream['values']:
                part = {'streams': [{'stream': stream['stream'], 'values': [value]}]}
                body = json.dumps(part, ensure_ascii=False, separators=(',', ':'))
                encoded_size = len(body.encode())
                if encoded_size > 900*1024:
                    raise BoundaryError('local_request_exceeds_transport_budget')
                fragments.append((event_id+':'+value[2]['fragment_index'], body, encoded_size))
        size = sum(part[2] for part in fragments)
        if size > self.queue_limit:
            raise BoundaryError('event_exceeds_queue_capacity')
        while True:
            with self.lock:
                missing = [part for part in fragments if not self.db.execute('SELECT 1 FROM queue WHERE event_id=?', (part[0],)).fetchone()]
                if self.usage()[1] + sum(part[2] for part in missing) <= self.queue_limit:
                    with self.db:
                        self.db.executemany('INSERT INTO queue(event_id,body,bytes) VALUES (?,?,?)', missing)
                        if checkpoint is not None:
                            self.set('journal_cursor', checkpoint)
                            self.set('journal_pem', pem or {})
                        if kernel is not None:
                            self.set('kernel_checkpoint', kernel)
                    return
            if stop is not None and stop.wait(.2):
                raise BoundaryError('stopped_before_queue_commit')
            time.sleep(.05)

    def checkpoint(self, cursor, pem):
        with self.lock, self.db:
            self.set('journal_cursor', cursor)
            self.set('journal_pem', pem)

    def first(self):
        with self.lock:
            return self.db.execute('SELECT id,body FROM queue ORDER BY id LIMIT 1').fetchone()

    def batch(self, records=256, request_budget=800*1024):
        """A bounded batch improves small-record throughput without a new queue."""
        with self.lock:
            rows = self.db.execute('SELECT id,body FROM queue ORDER BY id LIMIT ?', (records,)).fetchall()
        selected, streams, encoded_size = [], {}, 32
        for row_id, body in rows:
            if selected and encoded_size + len(body.encode()) > request_budget:
                break
            packet = json.loads(body)
            for stream in packet['streams']:
                key = json.dumps(stream['stream'], sort_keys=True)
                current = streams.setdefault(key, {'stream': stream['stream'], 'values': []})
                current['values'].extend(stream['values'])
            selected.append(row_id)
            encoded_size += len(body.encode())
        packet = {'streams': list(streams.values())}
        return selected, json.dumps(packet, ensure_ascii=False, separators=(',', ':'))

    def ack(self, row_ids):
        if isinstance(row_ids, int):
            row_ids = [row_ids]
        with self.lock, self.db:
            self.db.executemany('DELETE FROM queue WHERE id=?', ((value,) for value in row_ids))

    def circuit(self, value=None):
        with self.lock:
            if value is not None:
                with self.db:
                    self.set('delivery_circuit', bool(value))
            return self.get('delivery_circuit', False)


class Processor:
    def __init__(self, store: Store, labels: dict[str, str], spool_dir: str,
                 stop=None, max_entry_bytes=MAX_ENTRY_BYTES):
        self.store, self.labels = store, labels
        self.spool_dir, self.stop = spool_dir, stop
        self.max_entry_bytes = max_entry_bytes
        self.pem = store.get('journal_pem', {})
        self.partials = {}
        self.pending_bytes = 0
        self.counters = {'journal_records': 0, 'complete_entries': 0,
                         'kernel_records': 0, 'kernel_sequence_gaps': 0,
                         'kernel_overrun_events': 0}

    def packet(self, identity, timestamp, body, service, source, stream):
        chunks = split_transport(body)
        fragment_id = hashlib.sha256(identity.encode()).hexdigest()
        values = []
        for index, chunk in enumerate(chunks):
            metadata = {'fragment_id': fragment_id, 'fragment_index': str(index),
                        'fragment_count': str(len(chunks)), 'original_timestamp': str(timestamp)}
            values.append([str(timestamp + index), chunk, metadata])
        labels = self.labels | {'service': service, 'source': source, 'stream': stream}
        return {'streams': [{'stream': labels, 'values': values}]}

    def journal(self, entry):
        cursor = entry.get('__CURSOR')
        if not isinstance(cursor, str) or not cursor:
            raise BoundaryError('missing_journal_cursor')
        self.counters['journal_records'] += 1
        container = entry.get('CONTAINER_ID_FULL')
        if not container:
            if not self.partials:
                self.store.checkpoint(cursor, self.pem)
            return
        service = entry.get('CONTAINER_NAME')
        message = entry.get('MESSAGE', '')
        if isinstance(message, list):
            # journal JSON represents binary fields as byte arrays.
            try:
                message_bytes = bytes(message)
            except (ValueError, TypeError):
                raise BoundaryError('invalid_binary_journal_message') from None
        elif isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            raise BoundaryError('invalid_container_journal_message')
        if not isinstance(service, str) or not service:
            raise BoundaryError('invalid_container_journal_fields')
        stream = 'stderr' if str(entry.get('PRIORITY')) == '3' else 'stdout'
        state_key = container + ':' + stream
        timestamp = (timestamp_ns(entry['SYSLOG_TIMESTAMP']) if entry.get('SYSLOG_TIMESTAMP')
                     else int(entry['__REALTIME_TIMESTAMP']) * 1000)
        partial_id = entry.get('CONTAINER_PARTIAL_ID')
        identity = 'journal:' + cursor
        if partial_id:
            key = (container, stream, partial_id)
            try:
                ordinal = int(entry['CONTAINER_PARTIAL_ORDINAL'])
            except (KeyError, ValueError, TypeError):
                raise BoundaryError('invalid_partial_ordinal') from None
            if key not in self.partials:
                if ordinal != 1 or len(self.partials) >= MAX_PARTIAL_STREAMS:
                    raise BoundaryError('partial_sequence_start_missing_or_capacity')
                self.partials[key] = {'ordinal': 0, 'timestamp': timestamp,
                    'identity': identity, 'size': 0,
                    'file': tempfile.SpooledTemporaryFile(max_size=256*1024, dir=self.spool_dir)}
            partial = self.partials[key]
            encoded = message_bytes
            if ordinal != partial['ordinal'] + 1:
                raise BoundaryError('partial_sequence_gap')
            if partial['size'] + len(encoded) > self.max_entry_bytes or self.pending_bytes + len(encoded) > MAX_PENDING_BYTES:
                raise BoundaryError('raw_partial_spool_capacity')
            partial['file'].write(encoded)
            partial['ordinal'] = ordinal
            partial['size'] += len(encoded)
            self.pending_bytes += len(encoded)
            if str(entry.get('CONTAINER_PARTIAL_LAST')).lower() != 'true':
                return
            partial['file'].seek(0)
            message_bytes = partial['file'].read()
            partial['file'].close()
            self.pending_bytes -= partial['size']
            timestamp, identity = partial['timestamp'], partial['identity']
            del self.partials[key]
        elif len(message_bytes) > self.max_entry_bytes:
            raise BoundaryError('raw_entry_capacity')
        message = message_bytes.decode('utf-8', 'replace')
        redacted, opened = redact_pem(message, self.pem.get(state_key, False))
        if opened:
            self.pem[state_key] = True
        else:
            self.pem.pop(state_key, None)
        packet = self.packet(identity, timestamp, redacted, service, 'docker', stream)
        self.store.enqueue(identity, packet,
            checkpoint=cursor if not self.partials else None,
            pem=self.pem, stop=self.stop)
        self.counters['complete_entries'] += 1

    def kernel(self, raw: bytes, boot_id: str, realtime_offset_ns: int):
        header, separator, body = raw.partition(b';')
        if not separator:
            raise BoundaryError('invalid_kmsg_record')
        parts = header.split(b',')
        if len(parts) < 4:
            raise BoundaryError('invalid_kmsg_header')
        try:
            sequence, monotonic_us = int(parts[1]), int(parts[2])
        except ValueError:
            raise BoundaryError('invalid_kmsg_sequence_or_time') from None
        previous = self.store.get('kernel_checkpoint', {})
        if previous.get('boot_id') == boot_id:
            if sequence <= previous['sequence']:
                return
            if sequence > previous['sequence'] + 1:
                self.counters['kernel_sequence_gaps'] += sequence - previous['sequence'] - 1
        timestamp = realtime_offset_ns + monotonic_us * 1000
        if body.endswith(b'\n'):
            body = body[:-1]
        text = body.decode('utf-8', 'replace')
        # kmsg c flags can interleave; do not merge unrelated kernel records.
        opened = previous.get('pem', False) if previous.get('boot_id') == boot_id else False
        redacted, opened = redact_pem(text, opened)
        identity = 'kernel:' + boot_id + ':' + str(sequence)
        packet = self.packet(identity, timestamp, redacted, 'kernel', 'kernel', 'kernel')
        checkpoint = {'boot_id': boot_id, 'sequence': sequence, 'pem': opened}
        self.store.enqueue(identity, packet, kernel=checkpoint, stop=self.stop)
        self.counters['kernel_records'] += 1


def metric_counter(text, name):
    total = 0.0
    for line in text.splitlines():
        if line.startswith(name + '{') or line.startswith(name + ' '):
            try:
                total += float(line.rsplit(' ', 1)[1])
            except ValueError:
                pass
    return total


def drop_process_capabilities():
    """Open kmsg first, then remove permitted/effective/inheritable forever."""
    library = ctypes.CDLL('libcap.so.2', use_errno=True)
    library.cap_init.restype = ctypes.c_void_p
    library.cap_set_proc.argtypes = [ctypes.c_void_p]
    library.cap_free.argtypes = [ctypes.c_void_p]
    empty = library.cap_init()
    if not empty:
        raise BoundaryError('capability_allocation_failed')
    try:
        if library.cap_set_proc(empty) != 0:
            raise BoundaryError('capability_drop_failed')
    finally:
        library.cap_free(empty)
    fields = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('CapEff:', 'CapPrm:', 'CapInh:')):
            key, value = line.split(':', 1)
            fields[key] = int(value.strip(), 16)
    if set(fields) != {'CapEff', 'CapPrm', 'CapInh'} or any(fields.values()):
        raise BoundaryError('capability_drop_readback_failed')


class Sender:
    def __init__(self, store, stop, api_url, metrics_url):
        for value, path in ((api_url, '/loki/api/v1/push'), (metrics_url, '/metrics')):
            parsed = urlparse(value)
            if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.path != path or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise BoundaryError('only_fixed_path_loopback_alloy_urls_allowed')
        self.store, self.stop = store, stop
        self.api_url, self.metrics_url = api_url, metrics_url
        self.last_dropped = store.get('last_dropped_counter', 0.0)
        self.resume_once = store.circuit()

    def check_circuit(self):
        if self.store.circuit() and not self.resume_once:
            return False
        try:
            with urllib.request.urlopen(self.metrics_url, timeout=2) as response:
                text = response.read(8 * 1024 * 1024).decode()
            dropped = metric_counter(text, 'loki_write_dropped_entries_total')
        except (OSError, urllib.error.URLError):
            return False
        if self.resume_once:
            # A controlled helper/CVM restart after repairing the endpoint is
            # the no-admin-port recovery path. Rebaseline once; a new permanent
            # rejection latches again and does not auto-clear in this process.
            with self.store.lock, self.store.db:
                self.store.set('last_dropped_counter', dropped)
                self.store.set('delivery_circuit', False)
            self.resume_once = False
            self.last_dropped = dropped
            return True
        self.last_dropped = self.store.get('last_dropped_counter', self.last_dropped)
        if dropped > self.last_dropped:
            # A permanent rejection would otherwise turn Alloy's own error logs
            # into an endless sequence of newly failing self-observation pushes.
            with self.store.lock, self.store.db:
                self.store.set('last_dropped_counter', dropped)
                self.store.set('delivery_circuit', True)
            return False
        self.last_dropped = dropped
        with self.store.lock, self.store.db:
            self.store.set('last_dropped_counter', dropped)
        return True

    def run(self):
        while not self.stop.is_set():
            if not self.check_circuit():
                self.stop.wait(1)
                continue
            row_ids, body = self.store.batch()
            if not row_ids:
                self.stop.wait(.2)
                continue
            request = urllib.request.Request(self.api_url, data=body.encode(),
                headers={'Content-Type': 'application/json', 'User-Agent': 'cvm-log-collector/' + VERSION}, method='POST')
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    accepted = response.status == 204
                if accepted:
                    # Local 204 acknowledges only Alloy's in-memory pipeline.
                    # Remote HTTP failure or Alloy shutdown can still lose it;
                    # a metric counter cannot prove per-fragment delivery.
                    self.store.ack(row_ids)
                    with self.store.lock, self.store.db:
                        self.store.set('last_local_api_ack_ns', time.time_ns())
                else:
                    self.stop.wait(1)
            except (OSError, urllib.error.URLError):
                # No per-request stdout logging: own logs must not form a loop.
                self.stop.wait(1)


def status(store, processor=None):
    count, size = store.usage()
    return {'version': VERSION, 'policy_version': POLICY_VERSION,
            'queue_entries': count, 'queue_bytes': size,
            'delivery_circuit_open': store.circuit(),
            'last_local_api_ack_ns': store.get('last_local_api_ack_ns'),
            'journal_cursor_present': bool(store.get('journal_cursor')),
            'journal_pem_streams': len(store.get('journal_pem', {})),
            'kernel_checkpoint_present': bool(store.get('kernel_checkpoint')),
            'counters': copy.deepcopy(processor.counters) if processor else {}}


def main():
    state_dir = Path(os.environ.get('STATE_DIR', '/var/lib/cvm-log-collector'))
    store = Store(state_dir / 'state.sqlite3', int(os.environ.get('QUEUE_MAX_BYTES', str(64*1024*1024))))
    if '--status' in sys.argv:
        print(json.dumps(status(store), separators=(',', ':')))
        return
    if '--clear-circuit' in sys.argv:
        # Operators clear only after fixing the endpoint and allowing the old
        # writer requests to settle. Read the actual current counter so that
        # errors from already rejected batches do not immediately re-latch it.
        metrics_url = os.environ.get('ALLOY_METRICS_URL', 'http://127.0.0.1:12345/metrics')
        parsed = urlparse(metrics_url)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.path != '/metrics' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BoundaryError('only_fixed_path_loopback_alloy_urls_allowed')
        with urllib.request.urlopen(metrics_url, timeout=3) as response:
            counter = metric_counter(response.read(8*1024*1024).decode(), 'loki_write_dropped_entries_total')
        with store.lock, store.db:
            store.set('last_dropped_counter', counter)
            store.set('delivery_circuit', False)
        print('{"delivery_circuit_cleared":true}')
        return
    labels = {'job': 'cvm-runtime', 'cvm_uuid': os.environ['CVM_UUID'], 'region': os.environ['CVM_REGION']}
    spool = os.environ.get('RAW_SPOOL_DIR', '/run/collector')
    Path(spool).mkdir(parents=True, exist_ok=True, mode=0o700)
    stop = threading.Event()
    processor = Processor(store, labels, spool, stop)
    children = []
    fatal = []

    def fail(reason):
        fatal.append(reason)
        stop.set()

    def signal_stop(*_):
        stop.set()
        for child in children:
            child.terminate()

    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGINT, signal_stop)

    mode = os.environ.get('INPUT_MODE', 'live')
    kernel_fd = None
    if mode == 'live':
        try:
            kernel_fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            raise BoundaryError('kernel_device_open_failed') from None
    drop_process_capabilities()

    def read_journal():
        args = ['journalctl', '--no-pager', '--all', '--no-tail', '--output=json', '--follow',
                '--output-fields=' + JOURNAL_FIELDS]
        cursor = store.get('journal_cursor')
        if cursor:
            args += ['--after-cursor=' + cursor]
        fixture_match = os.environ.get('JOURNAL_FIXTURE_MATCH')
        if fixture_match:
            if mode != 'journal-only-fixture' or not fixture_match.startswith('CONTAINER_TAG='):
                fail('invalid_fixture_journal_scope')
                return
            args.append(fixture_match)
        # Both volatile and persistent journals are discovered by journalctl.
        # No environment/labels from Docker inspect are read or requested.
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        children.append(child)
        try:
            for raw in child.stdout:
                if stop.is_set():
                    return
                processor.journal(json.loads(raw))
            if not stop.is_set():
                fail('journal_reader_exited')
        except (BoundaryError, ValueError, KeyError, TypeError, OSError):
            fail('journal_input_boundary_or_io_error')
        finally:
            child.terminate()

    def read_kernel():
        try:
            boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            offset = time.time_ns() - time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            fd = kernel_fd
            try:
                while not stop.is_set():
                    try:
                        raw = os.read(fd, 65536)
                        if raw:
                            processor.kernel(raw, boot_id, offset)
                        else:
                            stop.wait(.2)
                    except BlockingIOError:
                        stop.wait(.2)
                    except OSError as error:
                        if error.errno == errno.EPIPE:
                            processor.counters['kernel_overrun_events'] += 1
                        else:
                            raise
            finally:
                os.close(fd)
        except (BoundaryError, ValueError, KeyError, OSError):
            fail('kernel_input_boundary_or_io_error')

    sender = Sender(store, stop, os.environ.get('ALLOY_PUSH_URL', 'http://127.0.0.1:15140/loki/api/v1/push'),
                    os.environ.get('ALLOY_METRICS_URL', 'http://127.0.0.1:12345/metrics'))
    threads = [threading.Thread(target=sender.run, daemon=True)]
    if mode == 'fixture':
        # Native tests use the exact baked executable, with synthetic stdin.
        def read_fixture():
            try:
                for line in sys.stdin:
                    packet = json.loads(line)
                    if packet.get('kind') == 'kernel':
                        processor.kernel(packet['raw'].encode(), packet['boot_id'], packet['offset_ns'])
                    else:
                        processor.journal(packet)
                while store.first() and not stop.is_set():
                    stop.wait(.1)
                stop.set()
            except (BoundaryError, ValueError, KeyError, OSError):
                fail('fixture_input_boundary_or_io_error')
        threads.append(threading.Thread(target=read_fixture, daemon=True))
    elif mode == 'journal-only-fixture':
        threads.append(threading.Thread(target=read_journal, daemon=True))
    elif mode == 'live':
        threads.extend((threading.Thread(target=read_journal, daemon=True), threading.Thread(target=read_kernel, daemon=True)))
    else:
        raise BoundaryError('unsupported_input_mode')
    print(json.dumps({'event': 'cvm_log_collector_started', 'version': VERSION, 'input_mode': mode}), flush=True)
    for thread in threads:
        thread.start()
    while not stop.wait(.5):
        # Status is a local state artifact, never a raw-log/error-response dump.
        temporary = state_dir / 'status.tmp'
        temporary.write_text(json.dumps(status(store, processor), separators=(',', ':')))
        temporary.replace(state_dir / 'status.json')
    signal_stop()
    for thread in threads:
        thread.join(timeout=3)
    print(json.dumps({'event': 'cvm_log_collector_stopped', 'failed': bool(fatal),
                      'reason': fatal[0] if fatal else 'signal_or_fixture_complete',
                      **status(store, processor)}), flush=True)
    if fatal:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
