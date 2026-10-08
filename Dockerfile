# Runtime-only image around the prebuilt static binaries. CI puts them in
# docker/udns-<arch><variant> first (see .github/workflows/ci.yml).
FROM scratch
ARG TARGETARCH
ARG TARGETVARIANT
COPY --chmod=0755 docker/udns-${TARGETARCH}${TARGETVARIANT} /udns
COPY config.example.toml /etc/udns.toml
# Creates /etc/udns for the default cache_file (scratch has no mkdir).
WORKDIR /etc/udns
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/udns"]
CMD ["/etc/udns.toml"]
