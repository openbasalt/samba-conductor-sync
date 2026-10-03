# Quality gates and builds for conductor-sync. GOWORK=off: the module is
# checked on its own (go.mod points at ../ad with a replace directive).
export GOWORK := off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
FUZZTIME ?= 20s

.PHONY: build test check fmt vet staticcheck vulncheck fuzz lab-test tools

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor-sync ./cmd/conductor-sync

test:
	go test -race ./...

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags lab ./internal/labtest/

staticcheck: tools
	$(STATICCHECK) ./...
	$(STATICCHECK) -tags lab ./internal/labtest/

vulncheck: tools
	$(GOVULNCHECK) ./...

fuzz:
	go test -run XXX -fuzz FuzzTemplate -fuzztime $(FUZZTIME) ./internal/mapping/

# Integration tests on server-home: Samba AD in the sync lab + the fake
# Directory API (scripts/lab-test.sh; the lab: scripts/synclab.sh).
lab-test:
	./scripts/lab-test.sh

tools:
	@test -x $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@latest
