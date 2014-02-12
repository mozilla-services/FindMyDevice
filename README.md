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

Install:
---
cd to $InstallRoot

. install.bash

This should fetch and install all required packages

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

