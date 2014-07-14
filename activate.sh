#!/bin/bash

set -e

echo "Setting GOPATH and GOBIN"
export GOPATH="${PWD}/Godeps/_workspace"
export GOBIN=$PWD
