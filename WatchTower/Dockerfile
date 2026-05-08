FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /watchtower ./cmd/watchtower
RUN mkdir -p /var/lib/watchtower && chown 65532:65532 /var/lib/watchtower

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /watchtower /usr/local/bin/watchtower
COPY --chown=nonroot:nonroot --from=builder /var/lib/watchtower /var/lib/watchtower
COPY rules/ /etc/watchtower/rules/
COPY decoders/ /etc/watchtower/decoders/
COPY cdb/ /etc/watchtower/cdb/
EXPOSE 50051 9400
USER nonroot:nonroot
ENTRYPOINT ["watchtower"]
