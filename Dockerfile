# Start from a Debian image with the latest version of Go installed
# and a workspace (GOPATH) configured at /go.
FROM --platform=$BUILDPLATFORM golang:1.24.2 AS build
ARG TARGETARCH
ARG BUILDPLATFORM
WORKDIR /app/
ADD . .

RUN GOARCH=$TARGETARCH make build
# RUN ls /go/src/github.com/Himanshu-216
FROM debian:bookworm-slim

COPY --from=build /app/bin/ssh-exporter /ssh-exporter

ENTRYPOINT ["/ssh-exporter"]

EXPOSE 9898