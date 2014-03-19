wmf
===

Where's My Fox (large server)

This server is still under development.

https://wiki.mozilla.org/Services/WheresMyFox#Server_API_Reference.2FDocumentation

Prerequisites:
---
You will need:
* A postgres database
* golang 1.3

How to install:
---
* set GOPATH to the root install directory (e.g. export GOPATH=`pwd`)
* run ./install.bash
* copy config-example.ini to config.ini
* modify config.ini to reflect your system and preferences.

Running:
---

GOPATH needs to be set to the root install directory.
e.g.
    $ GOPATH=`pwd` go run main.go

TODO:
---
* Add i18n support for display based on request language
* Add final name
* Nick's go at layout
* Add multi-host support for updates.
** route updates to connected server?

