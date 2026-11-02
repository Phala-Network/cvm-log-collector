# Releasing CVM Log Collector

Maintain source on `main` and use immutable `vMAJOR.MINOR.PATCH` tags. The
current published version is `v0.1.0`. Its source tag identifies the tested
build commit; later documentation commits do not move that tag or change the
published runtime bytes.

## Qualify one candidate

1. Review the implementation, Dockerfile, tests, license, and README together.
   Keep deployment credentials, host paths, raw production logs, and temporary
   evidence outside the source repository. Document the actual CLI, configuration,
   queue/checkpoint semantics, permissions, and known limits.
2. Integrate the reviewed source into `main` and record the exact commit. Run
   focused source tests on the approved Linux builder, then build one candidate
   from that commit and the Dockerfile's immutable base image. Keep dependencies
   inside the image and credentials out of build arguments, layers, and logs.
3. Test the resulting final image without source mounts or runtime installation.
   Cover non-credential body preservation, credential redaction, Docker partials,
   cross-entry private keys, long/multiline entries, source identity and time,
   restart/checkpoint/queue behavior, new and short-lived containers, and the
   actual journal/kernel access permitted by the target. Record unsupported
   cases rather than claiming lossless delivery.

## Publish source before the image

After the candidate has passed review and the requested checks:

1. Create the component repository if needed, publish `main`, and push an
   annotated version tag resolving to the exact build-source commit. Never move
   or reuse an existing published tag.
2. Publish a GitHub Release for that tag with the source commit, base image
   identity, build recipe, final builder-local image ID, relevant test results,
   and limits. A draft Release does not satisfy this step.
3. Read back the remote tag target and published Release. Record both URLs and
   confirm that their source identity matches the qualified candidate.
4. Tag and push the already tested final image to
   `ghcr.io/phala-network/cvm-log-collector:<version>` using the same version
   as the source tag, for example `v0.1.0`. Reuse the qualified image;
   rebuild only when its inputs or runtime bytes change.
5. Read back the registry digest and verify the intended pull path. Add the
   immutable `<version>@sha256:<digest>` reference to the Release and hand it to
   the deployment owner. Image publication does not establish CVM acceptance.

## Minimal release receipt

Keep one short release receipt containing:

- Source repository, exact commit, remote tag, and published Release URL.
- Immutable base image, Dockerfile/build command, and final tested image ID.
- Focused source/final-image results with execution environment and limits.
- Published image tag and immutable digest after registry read-back.

Do not include credentials or customer log bodies. Keep detailed fixture
outputs in the task's private evidence, and summarize the relevant results in
the public Release.
