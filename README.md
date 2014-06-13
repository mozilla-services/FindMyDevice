# fmd

Find My Device (large server)

This server is still under development.

https://wiki.mozilla.org/Services/WheresMyFox#Server_API_Reference.2FDocumentation

## Prerequisites:

You will need:

- A postgres database
- golang 1.3 or greater
- node.js & npm

## How to install:

- set `GOPATH` to the root install directory (e.g. ``export GOPATH=`pwd` ``)
- run `./install.bash`
  - for Production level installs, you will need to also run:
    `grunt build` in the ./static library. This will create a
    ./static/dist directory containing prebuilt items.
- copy [config-example.ini](config-sample.ini) to config.ini
- modify config.ini to reflect your system and preferences.

## Running:

`GOPATH` needs to be set to the root install directory. e.g.

```sh
$ GOPATH=`pwd` go run main.go
```
