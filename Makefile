.PHONY : test

build:
	go install github.com/mozilla-services/FindMyDevice

test: build
	go test github.com/mozilla-services/FindMyDevice/wmf/storage -cover
