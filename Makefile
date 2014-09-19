HERE= $(shell pwd)
DEPS= $(HERE)/.godeps
BIN=$(DEPS)/bin
GOPATH:=$(DEPS):$(HERE):$(GOPATH)
EXEC=FindMyDevice
GPM=GOPATH=$(GOPATH) $(HERE)/gpm
GO=GOPATH=$(GOPATH) go

.PHONY : all install build clean test

all: build

$(DEPS):
	mkdir -p .godeps
	$(GPM) install

install: $(DEPS)
	@echo $(GOPATH)
	@echo "installed"

build: $(DEPS)
	$(GO) build -o $(EXEC) github.com/mozilla-services/FindMyDevice

clean:
	rm -f $(EXEC)
	rm -rf $(DEPS)

test:
	$(GO) test github.com/mozilla-services/FindMyDevice/wmf -cover
	#$(GO) test github.com/mozilla-services/FindMyDevice/wmf/storage -cover

run:
	$(EXEC)
