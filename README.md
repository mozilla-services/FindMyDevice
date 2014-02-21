wmf
===

Where's My Fox (large server)

This server is still under development.

https://wiki.mozilla.org/Services/WheresMyFox#Server_API_Reference.2FDocumentation

Things You'll need:
---

 * A postgres db server
 * A recent copy of golang


How to install:
---
* set GOPATH to the root install directory (e.g. export GOPATH=`pwd`)
* run ./install.bash
* copy config-example.ini to config.ini
* modify config.ini to reflect your system and preferences.

TODO:
---
* Add i18n support for display based on request language
* Add final name
* Nick's go at layout
* Add multi-host support for updates.
** route updates to connected server?

