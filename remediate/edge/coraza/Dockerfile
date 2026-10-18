# Build Caddy with OWASP Coraza WAF plugin
FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2@v2.0.0

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
