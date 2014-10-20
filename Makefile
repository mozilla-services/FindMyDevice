.PHONY : test build protobuf

protobuf:
	PBROOT=Godeps/_workspace/src/code.google.com/p/gogoprotobuf
	GOPATH=Godeps/_workspace:. protoc --gogo_out=. \
	    -I=.:${PBROOT}:${PBROOT}/protobuf \
	    util/*.proto

build:
	go install github.com/mozilla-services/FindMyDevice

test: build
	go test github.com/mozilla-services/FindMyDevice/wmf/storage -cover
