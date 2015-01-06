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
	else \
		echo "!! Using existing config.ini file       !!\n";\
		echo "!! Be sure to check for new changes     !!\n";\
	fi

$(DEPS):
	mkdir -p .godeps
	$(GPM) install

install: config.ini $(DEPS)
	@echo "installed"

#Usually, not required, but if protobuf changes, moves, etc, this will rebuild.
util/pblog.pb.go:
	protoc -I$(DEPS)/src/github.com/gogo/protobuf \
	    -I$(DEPS)/src/github.com/gogo/protobuf/protobuf \
	    -I$(DEPS) \
	    --gogo_out=$(DEPS) \
	    util/pblog.proto
npm-installed:
	cd $(HERE)/static; npm install -g grunt && npm install -g grunt-cli && npm install -g bower && npm install --silent
	touch $(HERE)/npm-installed

FindMyDevice:
	$(GO) build -o $(EXEC) github.com/mozilla-services/FindMyDevice

build: npm-installed install util/pblog.pb.go FindMyDevice

build-prod: build
	cd static; grunt build

clean:
	rm -f $(EXEC)
	rm -rf $(DEPS)
	rm -rf $(HERE)/static/dist
	rm -rf $(HERE)/static/node_modules
	rm -rf $(HERE)/static/style
	rm -rf $(HERE)/static/OpenLayers-*
	rm -rf $(HERE)/static/openlayers*
	rm $(HERE)/npm-installed

test:
	$(GO) test github.com/mozilla-services/FindMyDevice/wmf -cover
	#$(GO) test github.com/mozilla-services/FindMyDevice/wmf/storage -cover

run:
	$(EXEC)
