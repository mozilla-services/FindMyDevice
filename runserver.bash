#!/bin/bash

GOPATH="$(pwd)/.godeps:$(pwd)" go run main.go $@
