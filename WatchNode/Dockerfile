## Multi-stage build for WatchNode agent and manager

FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/watchnode ./cmd/agent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/watchnode-manager ./cmd/manager

FROM gcr.io/distroless/base-debian12:nonroot AS agent
WORKDIR /
COPY --from=build /out/watchnode /usr/local/bin/watchnode
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/watchnode"]

FROM gcr.io/distroless/base-debian12:nonroot AS manager
WORKDIR /
COPY --from=build /out/watchnode-manager /usr/local/bin/watchnode-manager
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/watchnode-manager"]
