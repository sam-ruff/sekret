# The release image: the static binary from the release build, CA certificates and nothing else.
# Build the binary first with scripts/build-release.sh, which writes dist/sekret-linux-amd64.
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS base
RUN apk add --no-cache ca-certificates && mkdir -p /data && chown 65532:65532 /data

FROM scratch

ARG GIT_SHA
ARG VERSION
LABEL org.opencontainers.image.title="sekret" \
      org.opencontainers.image.description="Self-hosted secrets manager: server, CLI and Kubernetes operator in one binary" \
      org.opencontainers.image.source="https://github.com/sam-ruff/sekret" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base --chown=65532:65532 /data /data
COPY --chmod=0755 dist/sekret-linux-amd64 /usr/local/bin/sekret

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SEKRET_LISTEN=0.0.0.0:8080 \
    SEKRET_DATABASE_URL=sqlite:///data/sekret.db?mode=rwc
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/sekret"]
CMD ["server"]
