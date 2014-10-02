Testing
===

The current smoketest.py is temporary. It was built to do integration
testing against the server and will eventually be replaced by a proper
load tester. It's subject to change and abuse.

If you want to use this for whatever evil reason, you'll need to do
the following:

1. edit ../config.ini
* auth.disabled=true # turns off verifier
* auth.no\_secure\_cookie=true # only needed if you're not doing https
* log.level=3 # or higher. (I run 10)

2. cp {fake\_,}assert.fxa.dump
3. edit assert.fxa.dump
4. s/\*\* YOUR EMAIL HERE \*\*/your-email@your-host/ #(don't use that
verbatim, obviously)
5. s/\*\* YOUR FXA USER ID HERE \*\*/Returned UserID from
FirefoxAccounts/
You can get the firefox account ID by watching for "::Got User::" in
the logs.
6. buildAssert.py assert.fxa.dump > fake.fxa
7. edit test/config.ini and set "assert=" to the contents of fake.fxa

if you run smoketest.py, it should log in properly and start flooding
the server with location updates. You'll see the phone buzz around the
Mozilla Mountain View campus. This means it's working.

^C the smoketest.py script to make it stop.

