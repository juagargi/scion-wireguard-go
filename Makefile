PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

test: test-go test-experiment

test-go:
	go test ./...

# Unit tests of the experiment runner (tests/experiment). They need no Docker. Tests that need
# PyYAML, jsonschema or SCION_DIR are skipped without them.
test-experiment:
	python3 -m unittest discover -s tests/experiment -p 'test_*.py'

# Runs every SCION integration test on a running tiny topology. Point it at the
# checkout holding that topology with SCION_DIR, e.g. make test-integration SCION_DIR=~/scion
test-integration:
	./tests/scion-integration.py $(if $(SCION_DIR),--scion-dir "$(SCION_DIR)") --test-all

clean:
	rm -f wireguard-go


SCION_FORK   ?= github.com/juagargi/scion
SCION_BRANCH ?= hummingbird-endhost

hummingbird-update-external-replace:
	GOFLAGS=-mod=mod GONOSUMDB=* GONOSUMCHECK=1 go mod edit -replace github.com/scionproto/scion=$(SCION_FORK)@$(SCION_BRANCH)
	go mod tidy



.PHONY: all clean test test-go test-integration test-experiment install generate-version-and-build
