DEPPATH=${PWD}/Godeps/_workspace
GOPATH=${DEPPATH}:${PWD}
PBROOT=${DEPPATH}/src/code.google.com/p/gogoprotobuf

.PHONY : test build protobuf
all: build

# Build protobuf (since it's a bit complicated)
protobuf:
	GOPATH=${GOPATH} go get -d code.google.com/p/gogoprotobuf
	GOPATH=${GOPATH} protoc --gogo_out=. \
	    -I=.:${PBROOT}:${PBROOT}/protobuf \
	    util/*.proto

build: protobuf
	go install github.com/mozilla-services/FindMyDevice

test: build
	go test github.com/mozilla-services/FindMyDevice/util -cover
	go test github.com/mozilla-services/FindMyDevice/wmf -cover
	# Holding off on testing storage since RCS is hardwired
	# to use fmd:fmd -host localhost
	#go test github.com/mozilla-services/FindMyDevice/wmf/storage -cover
