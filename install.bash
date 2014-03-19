#! /bin/bash
echo "Installing required go libraries..."
if ( "$GOPATH" == "" ); then
    echo Setting GOPATH to current directory.
    GOPATH=`pwd`
fi
git submodule update --init
for req in `grep -v "^#" go-prod.deps`; do
    echo -n "   $req..."
    go get -v $req
    echo " done"
done
set -e
echo "Libraries installed"
if [ ! -e config.ini ]; then
    echo "Copying sample ini file to config.ini"
    cp config-sample.ini config.ini
fi
if [ ! -z "$HOST" ]; then
    echo "Setting local shard host name"
    echo "shard.current_host = $HOST:8080" >> config.ini
fi
echo "Please edit config.ini for local settings."
