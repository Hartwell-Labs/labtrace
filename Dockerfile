# LabTrace — multi-stage build (static musl binary)
FROM rust:1.83-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release

FROM scratch
LABEL org.opencontainers.image.title="labtrace"
LABEL org.opencontainers.image.description="Forensic timeline reconstruction and cross-process threat correlation for Linux audit telemetry"
LABEL org.opencontainers.image.source="https://github.com/Hartwell-Labs/labtrace"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /src/target/release/labtrace /usr/local/bin/labtrace
ENTRYPOINT ["/usr/local/bin/labtrace"]
