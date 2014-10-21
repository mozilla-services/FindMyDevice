HERE = $(shell pwd)
BIN = $(HERE)/bin
DEPS = $(HERE)/Godeps
GOBIN = $(HERE)/bin
GOPATH = $(DEPS):$(HERE)
GO = GOPATH=$(GOPATH) go
PKG = github.com/mozilla-services/FindMyDevice

.PHONY : test build clean

all: build

clean:
	$(GO) clean
	rm -rf bin $(DEPS)
build:
	$(GO) install $(PKG)

test: build
	$(GO) test $(PKG)/wmf -cover
	#$(GO) test $(PKG)/wmf/storage -cover
