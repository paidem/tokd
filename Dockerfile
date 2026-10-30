FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tokd ./cmd/tokd \
 && mkdir -p /out/data /out/key

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/tokd /tokd
COPY --from=build --chown=nonroot:nonroot /out/data /data
COPY --from=build --chown=nonroot:nonroot /out/key /key
ENV TOKD_DATA=/data TOKD_ADDR=:19191
VOLUME /data
EXPOSE 19191
ENTRYPOINT ["/tokd"]
