# Everything compiles on the build host's native platform (no QEMU); only the
# tokd binary targets TARGETOS/TARGETARCH. Client downloads are the same in every image.
# CI builds the binaries outside Docker and replaces the "bin" and "downloads" stages
# with directories (docker buildx --build-context bin=... --build-context downloads=...).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS src
RUN apk add --no-cache make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM src AS tokd-build
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X github.com/paidem/tokd/internal/server.Version=$VERSION" -o /out/tokd-$TARGETOS-$TARGETARCH ./cmd/tokd

FROM scratch AS bin
COPY --from=tokd-build /out/ /

FROM src AS downloads-build
ARG VERSION=dev
RUN make dist DIST=/out VERSION=$VERSION

FROM scratch AS downloads
COPY --from=downloads-build /out/ /

FROM --platform=$BUILDPLATFORM alpine AS dirs
RUN mkdir -p /out/data /out/key

FROM gcr.io/distroless/static:nonroot
ARG TARGETOS TARGETARCH
LABEL org.opencontainers.image.source=https://github.com/paidem/tokd
COPY --from=bin /tokd-${TARGETOS}-${TARGETARCH} /tokd
COPY --from=downloads / /downloads
COPY --from=dirs --chown=nonroot:nonroot /out/data /data
COPY --from=dirs --chown=nonroot:nonroot /out/key /key
ENV TOKD_DATA=/data TOKD_ADDR=:19191 TOKD_DOWNLOADS=/downloads
VOLUME /data
EXPOSE 19191
ENTRYPOINT ["/tokd"]
