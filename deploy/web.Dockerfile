# Keymesh static web server: the existing scripts/serve.mjs plus the already-built
# Angular/WASM bundle (apps/web/dist/web/browser). Build context: apps/web.
# Nothing else enters the context (see web.Dockerfile.dockerignore): no node_modules,
# no sources, no keys, no .supervision.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
WORKDIR /app
COPY --chown=root:root scripts/serve.mjs scripts/serve.mjs
COPY --chown=root:root scripts/favicon.mjs scripts/favicon.mjs
COPY --chown=root:root dist/web/browser dist/web/browser
ARG KEYMESH_REVISION=unknown
LABEL org.opencontainers.image.title="keymesh-web" \
      org.opencontainers.image.description="Keymesh static web server (experimental, synthetic data only)" \
      org.opencontainers.image.revision="${KEYMESH_REVISION}"
ENV NODE_ENV=production HOST=127.0.0.1 PORT=4320
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4320/').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "scripts/serve.mjs", "4320"]
