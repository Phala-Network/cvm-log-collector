# CVM Log Collector

A small log reader for systemd-based Phala CVMs. It reads Docker container
records from the journal and kernel records from `/dev/kmsg`, applies
credential-only redaction, and forwards Loki JSON to a local Grafana Alloy
receiver. Alloy owns remote authentication and delivery.

**Status:** `main` is an unreleased candidate for `v0.1.0`. No image or release
is published yet. Runtime behavior and examples will be finalized against the
tested candidate before release.

## Runtime contract

The collector is designed for a dedicated, read-only container with:

- Docker's `journald` logging driver enabled for each container to collect.
- Read-only journal directories, machine identity, and `/dev/kmsg` access.
- A dedicated writable state volume for cursors, redaction state, and queueing.
- A local Alloy receiver in the same network namespace, with no published
  collector port. The collector receives no model-service or remote log token.

The packaged entrypoint is `python3 -u /app/collector.py`. Configuration uses
environment variables; see [configuration and delivery limits](docs/configuration.md).
The minimal container invocation will be finalized with the tested permission
profile before release.

The processing contract preserves non-credential log text, including payloads
and request IDs. Ordered Docker partial records are reassembled before
redaction. Private-key redaction state spans entries in the same container and
stream. Large supported entries are split into UTF-8 segments after redaction.
These are candidate requirements until the release's focused tests pass.

Journal retention, the kernel ring buffer, finite local storage, and downstream
queues bound delivery. A successful local Alloy response is not a durable
remote receipt; the collector does not promise exactly-once delivery. Release
notes describe the tested limits and failure behavior.

## Development and releases

Implementation, tests, and the image build recipe belong in this repository.
Deployment Compose belongs in
[phala-models-compose](https://github.com/Phala-Network/phala-models-compose).

Run the focused source tests with `python3 -m unittest -v test_collector` on the
approved Linux builder. Qualify the final image with the same journal, kernel,
redaction, restart, and local receiver fixtures before publishing it. See
[the release procedure](docs/releasing.md) for source/image ordering and the
release receipt.

Licensed under [Apache-2.0](LICENSE). Distribution packages in the base image
retain their own licenses and notices.
