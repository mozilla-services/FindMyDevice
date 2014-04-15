#!/usr/bin/python

from __future__ import print_function

"""
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""


"""
This is a simple test to ensure minimal API operations for the server
"""


from pprint import pprint
from string import Template
import ConfigParser
import base64
import getopt
import hashlib
import hmac
import json
import os
import random
import requests
import sys
import time
import urlparse
import pdb
import websocket
import signal
import logging


import gevent
from gevent import monkey
from gevent.queue import Queue


monkey.patch_all(thread=False)
FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(format=FORMAT)


def genHash(body, ctype="application/json"):
    """ Generate a HAWK hash from the body of the sent message
    """
    if len(body) == 0:
        return ""
    marshalStr = "%s\n%s\n%s\n" % (
        "hawk.1.payload",
        ctype,
        body)
    bhash = base64.b64encode(hashlib.sha256(marshalStr).digest())
    #print("Hash:<<%s>>\nBHash:<<%s>>\n" % (marshalStr, bhash))
    return bhash


def genHawkSignature(method, urlStr, bodyHash, extra, secret,
                     now=None, nonce=None, ctype="application/json"):
    """ Generate a HAWK signature from the content to be sent
    """
    url = urlparse.urlparse(urlStr)
    path = url.path
    host = url.hostname
    port = url.port
    if nonce is None:
        nonce = os.urandom(5).encode("hex")
    if now is None:
        now = int(time.time())
    marshalStr = "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n" % (
        "hawk.1.header",
        now,
        nonce,
        method.upper(),
        path,
        host.lower(),
        port,
        bodyHash,
        extra)
    #print("Marshal Str: <<%s>>\nSecret: <<%s>>\n" % (marshalStr, secret)
    mac = hmac.new(secret.encode("utf-8"),
                   marshalStr.encode("utf-8"),
                   digestmod=hashlib.sha256).digest()
    # print("mac: <<" + ','.join([str(ord(elem)) for elem in mac]) + ">>\n")
    #print("mac: " + base64.b64encode(mac) + "\n")
    return now, nonce, base64.b64encode(mac)


def parseHawkHeader(header):
    """ Parse the HAWK auth header elements
    """
    result = {}
    if header[:4].lower() != "hawk":
        return None
    elements = header[5:].split(", ")
    for elem in elements:
        bits = elem.split("=")
        result[bits[0]] = bits[1].replace('"', '')
    return result


def checkHawk(response, secret):
    """ Validate the HAWK header against the body
    """
    hawk = parseHawkHeader(response.headers.get("authorization"))
    ct = response.headers.get('content-type')
    bodyhash = genHash(response.text, ct)
    _, _, mac = genHawkSignature(response.request.method,
                                 response.request.url,
                                 bodyhash,
                                 hawk.get("ext"),
                                 secret,
                                 hawk["ts"],
                                 hawk["nonce"],
                                 ct)
    # remove "white space
    return mac.replace('=', '') == hawk["mac"].replace('=', '')


def geoWalk():
    """ Return a randomish location within a mile or so of a location.
    """
    return (random.randint(0, 999) * 0.000001)


def fakeLocation():
    """ Create a new, fake location
    """
    utc = int(time.time())
    lat = 37.3883 + geoWalk()
    lon = -122.0615 + geoWalk()
    return {"t": {"la": lat, "lo": lon, "ti": utc, "ha": True}}


def fakeUser():
    return "FakeUser_" + ("%012x" % rval()) + "@example.com"


def fakeAssertion(email=None):
    if email is None:
        email = fakeUser()
    return "%s.%s.%s" % (
        base64.b64encode(json.dumps({"alg": "fake"})),
        base64.b64encode(json.dumps({"public-key": {"algorithm": "None"},
                                     "iat": int(time.time()),
                                     "exp": int(time.time()) + 300,
                                     "principal": {"email": email},
                                     "iss": "login.example.org"})),
        "InvalidKey")


def getConfig(argv):
    """ Read in the config file
    """
    configFile = "config.ini"
    try:
        opts, args = getopt.getopt(argv, "c:", ["config="])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)
    for o, a in opts:
        if o in ("-c", "--config"):
            configFile = a
    config = ConfigParser.ConfigParser()
    print("Reading... %s\n" % configFile)
    config.read(configFile)
    return config


def registerNew(config,
                pushurl="http://example.com",
                deviceid="test1",
                assertion=None):
    """ Register a new fake device
    """
    tmpl = config.get("urls", "reg")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"))
    if assertion is None:
        assertion = config.get("main", "assertion")
        if assertion is None:
            assertion = fakeAssertion()
    # divy up based on scheme.
    regObj = {"assert": assertion,
              "pushurl": pushurl,
              "deviceid": deviceid}
    reply = send(trg, {}, regObj)
    cred = reply.json()
    print("Registered... %s" % json.dumps(cred))
    sendCmd(config, cred, fakeLocation(), None)
    return cred


def send(urlStr, cred, data, method="POST", user=None):
    """ Generic function that wraps data and sends it to the server
    """
    session = requests.Session()
    headers = {"content-type": "application/json"}
    datas = ""
    if data is not None:
        datas = json.dumps(data)
    if cred.get("secret") is not None:
        # generate HAWK auth header
        bodyHash = genHash(datas, "application/json")
        ts, nonce, mac = genHawkSignature(method, urlStr, bodyHash, "",
                                          cred.get("secret"))
        header = Template('Hawk id="$devid", ts="$ts", ' +
                          'nonce="$nonce", ext="$extra", ' +
                          'hash="$bhash", mac="$mac"'
                          ).safe_substitute(devid=cred.get("deviceid",
                                                           "test1"),
                                            extra="",
                                            bhash=bodyHash,
                                            ts=ts, nonce=nonce, mac=mac)
        #print("Header: %s\n" % (header))
        headers["Authorization"] = header
    cookies = {}
    if user is not None:
        uhash = (hashlib.sha256(user).digest()).encode('hex')
        cookies['user'] = uhash
    print("###Sending to: %s %s\n" % (urlStr, datas))
    req = requests.Request(method,
                           urlStr,
                           cookies=cookies,
                           data=datas,
                           headers=headers)
    prepped = req.prepare()
    response = session.send(prepped, timeout=3)
    if response.status_code != requests.codes.ok:
        pdb.set_trace()
        print("Response Not OK")
        requests.Response.raise_for_status()
    print("Response %s\n" % response.status_code)
    if response.headers.get("Authorization") is not None:
        if checkHawk(response, cred.get("secret")) is False:
            pdb.set_trace()
            print("HAWK Header failed")
    return response


def sendCmd(config, cred, cmd, user):
    """ Shorthand method to send a command to the server.
    """
    print("Sending Cmd %s\n" % json.dumps(cmd))
    tmpl = config.get("urls", "cmd")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"),
        devid=cred.get("deviceid", "test1"))
    return send(trg, cred, cmd, "POST", user)


def sendQ(config, cred, cmd, user):
    print("Sending user command %s" % json.dumps(cmd))
    if cmd == {}:
        return
    tmpl = config.get("urls", "que")

    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"),
        devid=cred.get("deviceid", "test1"))
    return send(trg, cred, cmd, "POST", user)


def rval():
        return random.randint(0, 281474976710655)


# ===
# Pretend we're a client.
class FakeClient:

    config = {}
    cred = {}
    pushURL = ""
    state = ""
    uaid = "00000000-dead-beef-0000-000000000000"
    chid = "00000000-deca-fbad-0000-"

    def on_open(self, ws):
        print("Socket Opened")
        self.state = "hello"
        ws.send(json.dumps({"messageType": "hello",
                            "uaid": self.uaid,
                            "channelIDs": []}))
        return

    def on_message(self, ws, rmessage):
        print("<<<Rcv'd:: " + self.state + ">>> " + rmessage)
        message = json.loads(rmessage)
        if self.state == "update":
            self.processPush(ws, message)
        if self.state == "register":
            self.state = "update"
            self.pushURL = message.get("pushEndpoint")
            print("Got push url, registering device:")
            self.register()
            return
        if self.state == "hello":
            self.state = "register"
            print("Sending Hello >>>\n")
            ws.send(json.dumps({"messageType": "register",
                                "channelID": self.chid}))
            return

    def on_error(self, ws, error):
        print("!!!Error:: %s" % error)
        pprint(self)

    def on_close(self, ws):
        print("Socket Closed")
        self.shutdown()

    def processPush(self, push_ws, message):
        #fetch a command
        cmd = sendCmd(self.config,
                      self.cred,
                      "",
                      self.user)
        self.processCmd(push_ws, cmd.json())

    def run(self):
        # connect and register with simplepush
        print("Running...")
        url = self.config.get("urls", "push")
        if url is None:
            url = "http://localhost:8080"
        self.ws = websocket.WebSocketApp(url,
                                         on_open=self.on_open,
                                         on_message=self.on_message,
                                         on_error=self.on_error,
                                         on_close=self.on_close)
        self.ws.run_forever()

    def processCmd(self, ws, cmd):
        # do stuff with command
        # send the result back to the tester
        """ Process the command like a client.
            Or a cat. Which it kinda does now.
        """
        #TODO: you can insert various responses to commands here
        # or just eat them like I'm doing right now.
        print("Command Recv'd: %s" % json.dumps(cmd))
        reply = {}
        if cmd != {}:
            if 'r' in cmd:
                print("Ringing for %s seconds" % cmd['r']['d'])
                reply = {"r": {"ok": True}}
            elif 'l' in cmd:
                print("Locking device with code %s" % cmd['l']['c'])
                if 'm' in cmd['l']:
                    print("with message \"%s\"" % cmd['l']['m'])
                reply = {"l": {"ok": True}}
            elif 'e' in cmd:
                print("Erasing device...")
                reply = {"e": {"ok": True}}
            elif 't' in cmd:
                print("Tracking device for %s seconds" % cmd['t']['d'])
                reply = {"t": {"ok": True}}
            else:
                pdb.set_trace()
                print("Unknown command")
                pprint(cmd)
                return
        # ack the command
        if reply != {}:
            print("\n============\n\n")
            self.outqueue.put(reply)

    def genDeviceId(self):
        # fake a new device id
        tok = base64.b32encode(os.urandom(5))
        prefix = ""
        try:
            prefix = self.config.get("main", "device.prefix")
        except:
            prefix = "test_"
        self.deviceId = "%s_%s" % (prefix, tok)
        return self.deviceId

    def __init__(self, config, inqueue, outqueue):
        self.config = config
        self.chid = self.chid + "%012x" % rval()
        print("Creating child %s" % self.chid)
        self.genDeviceId()
        # pass events via queues (Since there's only one
        # client per test instance at this time, shouldn't be
        # a problem?)
        self.inqueue = inqueue
        self.outqueue = outqueue
        self.user = fakeUser()
        self.assertion = fakeAssertion(email=self.user)
        # Generate a sufficiently random chid

    def register(self):
        self.cred = registerNew(self.config,
                                self.pushURL,
                                self.deviceId,
                                self.assertion)
        self.outqueue.put(self.cred)
        return self.cred

    def shutdown(self, a=None, b=None):
        #unregister push
        print("Unregistering chid %s" % self.chid)
        if self.ws is not None:
            self.ws.send(json.dumps({"messageType": "unregister",
                                     "channelID": self.chid}))
            self.ws.close()
        self.outqueue.put("kill")


# ===============
# faking a test client is... interesting.
# Since commands come from the server, and it's all handled via REST,
# things should scale fairly well. Still, this is not what the world is about.


def randomCommand():
    r = random.randint(0, 3)
    if r == 0:
        return {"t": {"d": 10}}
    if r == 1:
        return {"r": {"d": 10}}
    if r == 2:
        return {"l": {"m": "locked", "c": "0000"}}
    if r == 3:
        return {"e": {}}


def main(argv):
    config = getConfig(argv)

#    try:
#        creds = config.get("main", "cred")
#    except Exception:
#        creds = None
#    if creds is None:
#        cred = {}
#    else:
#        cred = json.loads(creds)
#
#    print ("Creds: %s" % creds)

    # create a new fake client
    # get queue structs
    inqueue = Queue()
    outqueue = Queue()
    client = FakeClient(config, inqueue, outqueue)
    signal.signal(signal.SIGINT, client.shutdown)
    job = gevent.spawn(client.run)
    # register a new device
    gevent.wait([job], timeout=1)

    print("Starting loop...")

    while True:
        try:
            thing = outqueue.get()
            if thing == "kill":
                gevent.kill(job)
                return
            print("Thing: %s" % thing)
            # send a random command
            if client.cred != {}:
                # time.sleep(random.randint(0,4))
                cmd = randomCommand()
                sendQ(config, client.cred, cmd, client.user)

        except:
            pass

#    print("Registering client... \n")
#    cmd, cred = registerNew(config)
#    while cmd is not None:
        # Burn through the command queue.
#        print("Processing commands...\n")
#        cmd = processCmd(config, cred, cmd)

    # Send a fake statement saying that the client has no passcode.
#    response = sendCmd(config, cred, {'has_passcode': False})
#    if response is not None:
#        print(response.text)
#    sendCmd(config, cred, {'l': {'ok': True}, 'has_passcode': True})


if __name__ == "__main__":
    main(sys.argv[1:])
