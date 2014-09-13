#! /bin/bash
# This script will build the go protobuf code required for logging
PBROOT=Godeps/_workspace/src/code.google.com/p/gogoprotobuf
GOPATH=Godeps/_workspace:. protoc --gogo_out=. \
    -I=.:$PBROOT:$PBROOT/protobuf \
    util/*.proto

