#!/bin/bash

. ./activate.sh

echo "Installing required go libraries..."
go install github.com/mozilla-services/FindMyDevice

echo "Libraries installed"
if [ ! -e config.ini ]; then
    echo "Copying sample ini file to config.ini"
    cp config-sample.ini config.ini
fi

echo "Installing static content"
pushd static
    npm install
popd
#if [ ! -z "$HOST" ]; then
#    echo "Setting local shard host name"
#    echo "shard.current_host = $HOST:8080" >> config.ini
#fi

echo "Please edit config.ini for local settings."
echo "Finished installation"
