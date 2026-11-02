# CVM Log Collector

A small log reader for systemd-based Phala CVMs. It reads Docker container
records from the journal and kernel records from `/dev/kmsg`, applies
credential-only redaction, and forwards Loki JSON to a local Grafana Alloy
receiver. Alloy owns remote authentication and delivery.

[v0.1.0](https://github.com/Phala-Network/cvm-log-collector/releases/tag/v0.1.0)
is available. Its tested build source is commit
`13cd1064897ffb9160297f587d3dd97b45f74799`; later documentation commits on
`main` describe that same release. The published image is:

```text
ghcr.io/phala-network/cvm-log-collector:v0.1.0@sha256:6f29b15de629b1517b72f843aed20029d49d5b2d4bf43ecf2461f24341ddef82
```

## Quick start

Docker on Linux can check the packaged executable without host-log access or
credentials:

```sh
IMAGE=ghcr.io/phala-network/cvm-log-collector:v0.1.0@sha256:6f29b15de629b1517b72f843aed20029d49d5b2d4bf43ecf2461f24341ddef82
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /var/lib/cvm-log-collector:rw,mode=0700 "$IMAGE" --status
```

Success prints JSON with `version` equal to `0.1.0` and an empty local queue.
This checks packaging; live collection also needs the runtime contract below.

## Runtime contract

The collector is designed for a dedicated, read-only container with:

- Docker's `journald` logging driver enabled for each container to collect.
- Read-only journal directories, machine identity, and `/dev/kmsg` access.
- A dedicated writable state volume for cursors, redaction state, and queueing.
- An 80 MiB private tmpfs at `/run/collector` for raw partial reconstruction.
- A local Alloy receiver in the same network namespace, with no published
  collector port. The collector receives no model-service or remote log token.

The packaged entrypoint is `python3 -u /app/collector.py`. Configuration uses
environment variables; see [configuration and delivery limits](docs/configuration.md).
Live collection starts as UID 0 with only `SYSLOG` available to open
`/dev/kmsg:r`; it clears effective, permitted, and inheritable process
capabilities before starting reader threads or journalctl. Use
`no-new-privileges`, a read-only root filesystem, and read-only journal and
machine-id mounts. The maintained deployment entrypoint is
[Phala production Compose](https://github.com/Phala-Network/phala-models-compose/tree/main/production).

The processing contract preserves non-credential log text, including payloads
and request IDs. Ordered Docker partial records are reassembled before
redaction. Private-key redaction state spans entries in the same container and
stream. Large supported entries are split into UTF-8 segments after redaction.
The release's final-image tests cover these paths; deployment acceptance
remains specific to the target CVM and receiver.

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
