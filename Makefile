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

# Run the two suites one after the other even under make -j, so their output does not interleave.
.NOTPARALLEL: test
test: test-go test-experiment

test-go:
	go test ./...

# The SCION checkout (hummingbird fork) of the integration tests; the same default as
# tests/scion-integration.py. Override it with e.g. make test SCION_DIR=~/scion
SCION_DIR ?= $(abspath $(CURDIR)/../scion)
# The Python of the virtual environment in .venv when there is one, else python3.
PYTHON ?= $(if $(wildcard .venv/bin/python3),.venv/bin/python3,python3)
# The SCION checkout whose hummbwtester the unit tests load: SCION_DIR when given (environment or
# command line), else the SCION Go module that go.mod pins, so that by default the tests use the
# hummbwtester version this repository builds with (tests/experiment/testsupport.py).
TEST_SCION_DIR = $(if $(filter file,$(origin SCION_DIR)),$$(go list -m -f '{{.Dir}}' github.com/scionproto/scion),$(SCION_DIR))

# Unit tests of the experiment runner (tests/experiment). They need no Docker, but they need
# PyYAML and hummbwtester (TEST_SCION_DIR): without them those tests fail, they are not skipped.
# Only the jsonschema checks are skipped without jsonschema. -b hides the output of passing tests
# (preflight messages, warnings) and shows it only for those that fail.
test-experiment:
	SCION_DIR="$(TEST_SCION_DIR)" $(PYTHON) -m unittest discover -b -s tests/experiment -p 'test_*.py'

# Runs every SCION integration test on a running tiny topology in SCION_DIR.
test-integration:
	$(PYTHON) ./tests/scion-integration.py --scion-dir "$(SCION_DIR)" --test-all

clean:
	rm -f wireguard-go


SCION_FORK   ?= github.com/juagargi/scion
SCION_BRANCH ?= hummingbird-endhost

hummingbird-update-external-replace:
	GOFLAGS=-mod=mod GONOSUMDB=* GONOSUMCHECK=1 go mod edit -replace github.com/scionproto/scion=$(SCION_FORK)@$(SCION_BRANCH)
	go mod tidy



.PHONY: all clean test test-go test-integration test-experiment install generate-version-and-build
