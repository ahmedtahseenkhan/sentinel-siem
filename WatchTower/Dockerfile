FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN GONOSUMDB="*" GOFLAGS="-mod=mod" go mod tidy && GONOSUMDB="*" GOFLAGS="-mod=mod" go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /watchtower ./cmd/watchtower
RUN mkdir -p /var/lib/watchtower && chown 65532:65532 /var/lib/watchtower

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /watchtower /usr/local/bin/watchtower
COPY --chown=nonroot:nonroot --from=builder /var/lib/watchtower /var/lib/watchtower
COPY rules/ /etc/watchtower/rules/
COPY decoders/ /etc/watchtower/decoders/
COPY cdb/ /etc/watchtower/cdb/
COPY sigma/rules/ /etc/watchtower/sigma/
EXPOSE 50051 9400
USER nonroot:nonroot
ENTRYPOINT ["watchtower"]
