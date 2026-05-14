FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN GONOSUMDB="*" GOFLAGS="-mod=mod" go mod tidy && GONOSUMDB="*" GOFLAGS="-mod=mod" go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /watchvault ./cmd/watchvault

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /watchvault /usr/local/bin/watchvault
EXPOSE 50052 9500
USER nonroot:nonroot
ENTRYPOINT ["watchvault"]
