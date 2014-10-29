HERE = $(shell pwd)
SHELL= /bin/bash
BIN = $(HERE)/bin
DEPS = $(HERE)/.godeps
GOBIN = $(HERE)/bin
GOPATH = $(DEPS):$(HERE)
GODEP = GOPATH=$(GOPATH) ./gpm
GO = GOPATH=$(GOPATH) go
PKG = github.com/mozilla-services/FindMyDevice
PBROOT=${DEPS}/src/code.google.com/p/gogoprotobuf

.PHONY : test build clean protobuf

all: build

clean:
	rm FindMyDevice
	$(GO) clean
	rm -rf $(DEPS)
	rm util/pblog.pb.go

.godeps/installed:
	@echo "installing dependencies..."
	$(GODEP) install && touch $(DEPS)/installed

FindMyDevice:
	@#Make sure we've got a link to this source directory
	-mkdir -p .godeps/src/github.com/mozilla-services && \
	    ln -s $(HERE) .godeps/src/$(PKG)
	@echo "Building go image..."
	$(GO) build -o FindMyDevice
	@# Should add in npm content here

# Build protobuf (since it's a bit complicated)
# This version was built with protoc v2.5.0
# It is included in the install for simplicity, however you're encouraged
# to build your own version using a local protoc to ensure that you're
# compatible with recipient versions.
util/pblog.pb.go:
	@# Ignore errors for this install
	-GOPATH=${GOPATH} go get -d code.google.com/p/gogoprotobuf
	GOPATH=${GOPATH} protoc --gogo_out=. \
	    -I=.:${PBROOT}:${PBROOT}/protobuf \
	    util/*.proto

build: .godeps/installed util/pblog.pb.go FindMyDevice

test:
	#$(GO) test $(PKG)/util -cover
	$(GO) test $(PKG)/wmf -cover
	@# Skipping storage tests because rds failures
	@# RDS currently presumes the test database is fmd:fmd@localhost
	#$(GO) test $(PKG)/wmf/storage -cover

