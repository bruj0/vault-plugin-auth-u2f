GOMAXPROCS = 4

PROJECT    = "github.com/bruj0/vault-plugin-auth-u2f"
NAME       = $(shell go run version/cmd/main.go name)
VERSION    = $(shell go run version/cmd/main.go version)
COMMIT     = $(shell git rev-parse --short HEAD)

GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)

LDFLAGS = \
	-s \
	-w \
	-X ${PROJECT}/version.GitCommit=${COMMIT}

# XC_* are the platforms for cross-compiling. Customize these values to suit
# your needs.
XC_OS      = linux
XC_ARCH    = amd64
XC_EXCLUDE =

# default is the default make command
default: dev

fmt:
	gofmt -w $(GOFMT_FILES)

# deps updates the project deps using golang/dep
deps:
	@dep ensure -v -update
.PHONY: deps

# dev builds and installs the plugin for local development
dev:
	@env \
		CGO_ENABLED=1 \
		go install \
			-ldflags="${LDFLAGS}" \
			./cmd/... && cp $(HOME)/go/bin/vault-plugin-auth-u2f plugins/u2f
.PHONY: dev 
# test runs the tests
test:
	@go test -timeout=60s -parallel=10 ./...
.PHONY: test

# xc compiles all the binaries using the local go installation
xc:
	@for OS in $(XC_OS); do \
		for ARCH in $(XC_ARCH); do \
			env \
				CGO_ENABLED=0 \
				GOOS=$${OS} \
				GOARCH=$${ARCH} \
				go build \
					-a \
					-o "pkg/$${OS}_$${ARCH}/${NAME}" \
					-ldflags "${LDFLAGS}"
					./cmd/... ; \
		done \
	done
.PHONY: xc
