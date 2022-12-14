# syntax=docker/dockerfile:1

### Build executable
FROM golang:1.19 as builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg go mod download
COPY cmd ./cmd
COPY internal ./internal
ENV CGO_ENABLED="0"
ENV GO111MODULE="on"
RUN --mount=type=cache,target=/go/pkg go build -o server ./cmd/main.go

### Target layer
FROM gcr.io/distroless/base-debian11
WORKDIR /
COPY --from=builder /workspace/server ./server
ENV GOTRACEBACK=all
ENTRYPOINT ["/server"]
