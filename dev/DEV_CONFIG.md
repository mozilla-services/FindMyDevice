# Configuring a Development Environment for Find My Device

## Prerequisites

This presumes that you've already created your postgres database and
run the create_db.sql script to initialize the tables. If not, close
this document and do so now. I'll wait.

## Loosening Auth
The next largest headache can be the Auth system. FMD uses Firefox
Auth (FxA), which requires a callback URL to be preregistered to a
given fxa.client_id & fxa.client_secret. If you're working on this
code, there is a developmental set of credentials which will send the
user to http://localhost:8080/oauth?...

```
fxa.login=https://oauth-stable.dev.lcip.org/v1/authorization
fxa.client_id=13a9e472ef33b1b8
fxa.client_secret=d17a43afb0d646dfe1dd6bfacfc5df3eb45f90e0adf86fedd68ffb22310f45f6
fxa.content.endpoint=https://stable.dev.lcip.org/profile/v1
```
(if you're running in a virtal machine, you'll have to hand modify the
callback URL to point to the correct entry (e.g.
http://192.168.7.10:8080/oauth...)

If that is difficult or annoying, you can also completely bypass user
auth using the following ***HIGHLY DEVELOPMENTAL NOT FOR PRODUCTION***
configuration options:

```
# Do not check the FxA auth system
# if NO assertion is sent as part of the login processes, this
# will default to email:"user@example.com" with a UAID of "user1"
# if an assertion is provided, the code will pull the email and userid
# from the assertion body. See Building Assertions later in this doc.
auth.disabled=true
# Force the system to log in as the following UAID & email
auth.force_user=0e4599f5cc3f43e8a833836f3ba1eb76 test+test@example.com
# Do not check the websocket signature value
auth.no_ws_check=true
# Do not check the CSRF token value (for REST calls)
auth.no_csrftoken=true
# Do not require session information to be only HTTPS
auth.no_secure_cookie=true
```
## Building Assertions
Located in the ./dev directory are two scripts and a template file
that should help you build completely bogus, absolutely invalid
assertions that FMD can parse in a dev environment.

Most of the template is junk. The bits you want to pay attention to
are "fxa-verifiedEmail" (which is where the user email is taken), and
"principal.email" (which contains the UAID as the local portion of the
email (the part that comes before the "@")).

Once you have modified the template the way you'd like, run the python
script "buildAssert.py assert.fxa.dump".

## Other config settings
### mapbox
You'll want to review all the settings, however the following are
important.
```mapbox.key``` this is the dev key for mapbox map displays. Please
sign up for your own free development key at
https://www.mapbox.com/developers/

### logger
Logging, by default, writes data in an optimized, machine readable
format. If you're not a machine, you may appreciate setting the
following:

```
# A prefix flag for the logging data
logger.logger_name=wm
# How verbose do you want your logging data? 10 == VERY verbose
logger.filter=10
# Make the output human readable
logger.logtype=human
# And where to write the data
logger.output=STDOUT
```
### Static
Ideally, static content (pages, css files, etc.) would be provided via
a protected environment like nginx, apache, or others. For a
development environment, however, this may not be quite as optimal. It
is possible for the server to provide these static elements by setting
```use_insecure_static``` to true.



