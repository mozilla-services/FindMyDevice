# Find My Device (fmd)

Find My Device (large server)

This server is still under development. Please note: The most stable version of this
server is the *master* branch. "dev" is marked as default to prevent accidental pushes
to the master branch. 

https://wiki.mozilla.org/Services/WheresMyFox#Server_API_Reference.2FDocumentation

## Prerequisites:

You will need:

- A postgres database
- golang 1.3 or greater
- node.js & npm

## How to install:

- run `./install.bash` (will generate "./FindMyDevice")
  - for Production level installs, you will need to also run:
    `grunt build` in the ./static library. This will create a
    ./static/dist directory containing prebuilt items.
- copy [config-example.ini](config-sample.ini) to config.ini
- modify config.ini to reflect your system and preferences.

## Running:

`GOPATH` needs to be set to the root install directory. e.g.

```sh
./runserver
```

## TODO:

- Add i18n support for display based on request language
- Add final name
- Nick's go at layout
- Add multi-host support for updates.
    - route updates to connected server?
