# Build Caddy with OWASP Coraza WAF plugin
FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2@v2.0.0

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Caddy stores runtime state under /data and /config; it listens on :8080, so no
# bind capability is needed
RUN addgroup -S caddy \
    && adduser -S -G caddy caddy \
    && mkdir -p /data/caddy /config/caddy \
    && chown -R caddy:caddy /data /config

USER caddy
