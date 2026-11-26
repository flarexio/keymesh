# Keymesh static web server: the existing scripts/serve.mjs plus the already-built
# Angular/WASM bundle (apps/web/dist/web/browser). Build context: apps/web.
# Nothing else enters the context (see web.Dockerfile.dockerignore): no node_modules,
# no sources, no keys, no .supervision.
#
# Runtime: only the `node` binary and the shared libraries it links,
# taken from the official node image, on the plain Alpine release that image is
# built on (same musl). No npm, npx, corepack, yarn or global node_modules.
# Both bases are pinned by digest; bump them together (same Alpine version).
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS node
# Every shared library node links from /usr/lib, per architecture (e.g. amd64
# also needs libatomic); musl itself comes with the Alpine base below.
RUN mkdir /runtime-libs && \
    ldd /usr/local/bin/node | awk '$3 ~ /^\/usr\/lib\// { print $3 }' | xargs -r -I{} cp -L {} /runtime-libs/ && \
    ls /runtime-libs

# alpine:3.24.4, the base of the node image above (/etc/alpine-release).
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /runtime-libs/ /usr/lib/
WORKDIR /app
COPY --chown=root:root scripts/serve.mjs scripts/serve.mjs
COPY --chown=root:root scripts/favicon.mjs scripts/favicon.mjs
COPY --chown=root:root dist/web/browser dist/web/browser
ARG KEYMESH_REVISION=unknown
LABEL org.opencontainers.image.title="keymesh-web" \
      org.opencontainers.image.description="Keymesh static web server (experimental, synthetic data only)" \
      org.opencontainers.image.revision="${KEYMESH_REVISION}"
ENV NODE_ENV=production HOST=127.0.0.1 PORT=4320
# Unprivileged (no named user in plain Alpine; compose also sets 1000:1000).
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4320/').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "scripts/serve.mjs", "4320"]
