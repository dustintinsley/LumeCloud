# Streamen Cloud on plain workerd (the open-source Workers runtime), for
# self-hosting without a Cloudflare account. See "Docker" in README.md.
#
#   docker build -t streamen-cloud .
#   docker run -p 8787:8787 -v streamen-data:/data -e SIGNUP=open streamen-cloud

FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json wrangler.jsonc ./
COPY src ./src
# Bundle exactly as `wrangler deploy` would, without uploading anything.
RUN npx wrangler deploy --dry-run --outdir dist \
 && cp "$(find node_modules/@cloudflare -path '*/workerd-linux-*/bin/workerd' | head -n 1)" /workerd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /app streamen \
 && mkdir -p /data && chown streamen /data
WORKDIR /app
COPY --from=build /workerd /usr/local/bin/workerd
COPY --from=build /src/dist/index.js ./dist/index.js
COPY docker/config.capnp docker/ratelimit.js ./

ARG VERSION=docker
ENV VERSION=${VERSION} \
    SIGNUP=invite
USER streamen
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8787 && printf 'GET /healthz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && head -n 1 <&3 | grep -q ' 200 '"]
ENTRYPOINT ["workerd", "serve", "--experimental", "config.capnp"]
