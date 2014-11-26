HERE= $(shell pwd)
DEPS= $(HERE)/.godeps
BIN=$(DEPS)/bin
GOPATH:=$(DEPS):$(HERE):$(GOPATH)
EXEC=FindMyDevice
GPM=GOPATH=$(GOPATH) $(HERE)/gpm
GO=GOPATH=$(GOPATH) go

.PHONY : all install build clean test

all: build

config.ini:
	@if [ ! -f config.ini ]; then \
		cp config-sample.ini config.ini; \
		echo "\n!! Sample config copied to config.ini !!"; \
		echo "!! Some modification required           !!\n"; \
	fi

$(DEPS):
	mkdir -p .godeps
	$(GPM) install

install: config.ini $(DEPS)
	@echo "installed"

build: install
	$(GO) build -o $(EXEC) github.com/mozilla-services/FindMyDevice

clean:
	rm -f $(EXEC)
	rm -rf $(DEPS)

test:
	$(GO) test github.com/mozilla-services/FindMyDevice/wmf -cover
	#$(GO) test github.com/mozilla-services/FindMyDevice/wmf/storage -cover

run:
	$(EXEC)
