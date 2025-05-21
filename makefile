pkgs := $(shell go list ./...)

BRANCH      ?= $(shell git rev-parse --abbrev-ref HEAD)
BUILDDATE   ?= $(shell date --iso-8601=seconds)
BUILDUSER   ?= $(shell whoami)@$(shell hostname)
REVISION    ?= $(shell git rev-parse HEAD)
TAG_VERSION ?= $(shell git describe --tags --abbrev=0)

VERSION_LDFLAGS := \
  -X github.com/prometheus/common/version.Branch=$(BRANCH) \
  -X github.com/prometheus/common/version.BuildDate=$(BUILDDATE) \
  -X github.com/prometheus/common/version.BuildUser=$(BUILDUSER) \
  -X github.com/prometheus/common/version.Revision=$(REVISION) \
  -X github.com/prometheus/common/version.Version=$(TAG_VERSION) \

all: format build

format:
	@echo ">> formatting code"
	go fmt $(pkgs)

build:
	@echo ">> building code"
	CGO_ENABLED=0 go build -ldflags "$(VERSION_LDFLAGS)" -o bin/ssh-exporter -a 

