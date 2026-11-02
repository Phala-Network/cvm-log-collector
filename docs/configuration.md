# Configuration and delivery limits

This documents the current `v0.1.0` candidate. Interfaces and limits remain
subject to the focused release tests.

## Configuration

The packaged executable reads these environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CVM_UUID` | Required | Stable CVM identity for the `cvm_uuid` label. |
| `CVM_REGION` | Required | Region for the `region` label. |
| `STATE_DIR` | `/var/lib/cvm-log-collector` | Dedicated writable state directory. |
| `QUEUE_MAX_BYTES` | `67108864` | Maximum total serialized packet bytes queued locally. |
| `RAW_SPOOL_DIR` | `/run/collector` | Private temporary partial-record spool; mount this as tmpfs. |
| `ALLOY_PUSH_URL` | `http://127.0.0.1:15140/loki/api/v1/push` | Local Alloy JSON push endpoint. |
| `ALLOY_METRICS_URL` | `http://127.0.0.1:12345/metrics` | Local Alloy drop counter used to detect permanent delivery failures. |
| `INPUT_MODE` | `live` | Production reads both the journal and kernel; other modes are for fixtures. |

The Alloy URLs must use plain HTTP on `127.0.0.1`, with exactly the documented
paths and no embedded credentials, query, or fragment. Keep Alloy in the shared
collector/Alloy network namespace.
Give the collector only the variables above. Remote log credentials belong to
Alloy; the collector does not need a model-service token or Docker API access.

`--status` prints local queue, checkpoint, and delivery-circuit state without
printing log content. `--clear-circuit` clears a latched delivery circuit after
the operator has repaired the downstream rejection and allowed old writer
requests to settle. It reads the current local Alloy drop counter before
clearing the latch, so Alloy metrics must be reachable. Both use `STATE_DIR`
and can create a state database when one does not exist.

`INPUT_MODE=fixture` reads synthetic JSON records from stdin.
`INPUT_MODE=journal-only-fixture` reads only the journal; its optional
`JOURNAL_FIXTURE_MATCH` must start with `CONTAINER_TAG=`. These modes are test
interfaces, and are not substitutes for qualifying live kernel access.

## Sources and output

Docker must use the `journald` logging driver. The collector discovers both
volatile and persistent journals and selects records with `CONTAINER_ID_FULL`.
With no checkpoint it reads all available history, then follows new records.
Container name supplies `service`; journal priority distinguishes `stdout`
and `stderr`. Ordered Docker partials are joined as bytes with no inserted
newline, then decoded as one logical entry.
The first partial supplies the event identity and timestamp.

In live mode the collector opens `/dev/kmsg` read-only before dropping all
process capabilities, then uses the retained file descriptor. The reader uses
no destructive `syslog` syscall.
Boot identity and sequence number form the checkpoint. Kernel monotonic time
is converted using the current wall-clock offset; clock adjustments can affect
the resulting historical wall time. Kernel continuation records are kept
separate because unrelated records can interleave.

Each Loki stream has `job=cvm-runtime`, `cvm_uuid`, `region`, `service`,
`source=docker|kernel`, and `stream=stdout|stderr|kernel` labels. Supported large
entries use `fragment_id`, `fragment_index`, `fragment_count`, and
`original_timestamp` structured metadata. Fragment indexes start at zero and
wire timestamps increase by one nanosecond per fragment; the original event
time remains in metadata.

The collector redacts complete logical text before segmenting it. Recognized
private-key markers open a per-source-stream state that remains masked until
an explicit end marker, including after restart. No time or line-count limit
clears that state. Other recognized credentials use the expressions in
`credentials_only.py`; arbitrary non-credential text is not a reason to drop
an entry. Invalid UTF-8 is decoded with replacement, so arbitrary binary
payloads are not preserved byte for byte.

## State and boundaries

The candidate supports logical entries up to 32 MiB, up to 128 concurrent
partial sequences, and up to 64 MiB of pending raw partial bytes. Raw partials
use anonymous temporary files in the configured tmpfs. Persisted SQLite state
contains sanitized packets, checkpoints, and boolean private-key context.
Supported entries are split into UTF-8 segments of at most 240 KiB and at most
512 KiB after JSON string escaping. Control characters can require smaller
segments. Each segment is a separate queued record; all segments and
checkpoint/state changes for one logical event are enqueued atomically. Their
combined serialized size must fit the configured queue capacity. Local HTTP
batches select up to 256 queued records within an 800 KiB request budget.

Queue saturation applies backpressure. An invalid partial sequence, unsupported
size, or input I/O boundary stops the collector without printing the input or
advancing its checkpoint past the incomplete sequence. Source retention must
be long enough to survive that pause and the repair; the collector cannot
recover records already removed from the journal or kernel ring.

The journal checkpoint advances transactionally with sanitized queueing only
when no partial sequence is pending. A restart can replay journal records from
an earlier checkpoint. Queue event identities suppress duplicates still in the
queue; an entry already handed to Alloy can be replayed again.

The collector retries its local HTTP handoff and removes the selected SQLite
records after Alloy returns HTTP 204. `last_local_api_ack_ns` records that local
handoff. A timeout can cause a retry and duplicates. Local 204 acknowledges
Alloy's in-memory pipeline; a later Alloy crash, queue loss, or permanent remote
rejection can lose already handed-off entries. It is not a remote receipt or a
durable-storage proof. Successful deployment acceptance requires an actual Loki
query through the intended receiver.

Use a dedicated Alloy writer so its `loki_write_dropped_entries_total` describes
this collector's output. A rise in that counter latches the delivery circuit,
retaining later queued fragments until operator repair and `--clear-circuit`.
This stops a permanent failure from causing an endless chain of failing
collector-log deliveries. After repairing the endpoint, clear the latch with
`--clear-circuit`, or perform one controlled helper/CVM restart. On startup a
persisted latch receives one probe after Alloy metrics become reachable: the
collector resets the drop-counter baseline and tries sending again. A new
permanent rejection latches it again for that process; it does not continuously
auto-clear. This mechanism cannot recover entries that Alloy already
acknowledged locally and then dropped.
