HERE := $(shell pwd)
DEPS := $(HERE)/.godeps
BIN  := $(DEPS)/bin
GOGETTER := GOPATH=$(shell pwd)/.tmpdeps go get -d
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

go_vendor_idependencies:
	$(GOGETTER) golang.org/x/net/websocket
	$(GOGETTER) github.com/cactus/go-statsd-client/statsd
	$(GOGETTER) github.com/gogo/protobuf/proto
	$(GOGETTER) github.com/gogo/protobuf/protoc-gen-gogo
	$(GOGETTER) github.com/gogo/protobuf/gogoproto
	$(GOGETTER) golang.org/x/tools/cmd/cover
	$(GOGETTER) github.com/gorilla/context
	$(GOGETTER) github.com/gorilla/securecookie
	$(GOGETTER) github.com/gorilla/sessions
	$(GOGETTER) github.com/jessevdk/go-flags
	$(GOGETTER) github.com/lib/pq
	$(GOGETTER) github.com/rafrombrc/gospec/src/gospec
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -type d -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	cp -ar .tmpdeps/src/* vendor/
	rm -rf .tmpdeps

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
	go install github.com/mozilla-services/FindMyDevice

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
	go test -v github.com/mozilla-services/FindMyDevice/wmf -cover
	#$(GO) test github.com/mozilla-services/FindMyDevice/wmf/storage -cover
