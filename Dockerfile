# Everything compiles on the build host's native platform (no QEMU); only the
# tokd binary targets TARGETOS/TARGETARCH. Client downloads are the same in every image.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
RUN apk add --no-cache make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X github.com/paidem/tokd/internal/server.Version=$VERSION" -o /out/tokd ./cmd/tokd \
 && make dist DIST=/out/downloads VERSION=$VERSION \
 && mkdir -p /out/data /out/key

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source=https://github.com/paidem/tokd
COPY --from=build /out/tokd /tokd
COPY --from=build /out/downloads /downloads
COPY --from=build --chown=nonroot:nonroot /out/data /data
COPY --from=build --chown=nonroot:nonroot /out/key /key
ENV TOKD_DATA=/data TOKD_ADDR=:19191 TOKD_DOWNLOADS=/downloads
VOLUME /data
EXPOSE 19191
ENTRYPOINT ["/tokd"]
