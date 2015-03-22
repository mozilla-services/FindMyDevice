###1.4.4 (2015-03-20)
* **server:** Added frame buster headers

###1.4.3 (2014-12-22)

#### Bug Fixes

* **server:** Issue #303 - allow signup/signin [c01e1fb]
** strip user data and added test cases
* Converted metrics to NOTICE level events (for metrics tracking)

#### Features
* **server:** Added go cover to dependencies (because `make test`) [7b7c7f1]
** build version bump because prod deployment
** Added discrete log message for registrations (included user IP and
UA string for outreach tracking)

#### INSTALL NOTES
* Please set PRODUCTION logger.filter = 5
