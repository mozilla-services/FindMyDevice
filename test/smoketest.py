#!/usr/bin/python

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


global accuracy


def on_close(ws):
    print "## closed"


def on_error(ws, error):
    print "!! error:: " + error
    exit()


def on_message(ws, message):
    print "<<< Rcv'd:: " + ws.state + ">> " + message


def on_open(ws):
    print "## Opened"


def listener(url, devid):
    ws = websocket.WebSocketApp(url + devid)
    ws.run_forever()


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
    #print "Hash:<<%s>>\nBHash:<<%s>>\n" % (marshalStr, bhash)
    return bhash


def genHawkSignature(method, urlStr, bodyHash, extra, secret,
                     now=None, nonce=None, ctype="application/json"):
    """ Generate a HAWK signature from the content to be sent
    """
    url = urlparse.urlparse(urlStr)
    path = url.path
    host = url.hostname
    port = url.port
    if port is None:
        port = 80
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
    print "Marshal Str: <<%s>>\nSecret: <<%s>>\n" % (marshalStr, secret)
    mac = hmac.new(secret.encode("utf-8"),
                   marshalStr.encode("utf-8"),
                   digestmod=hashlib.sha256).digest()
    print "mac: <<" + ','.join([str(ord(elem)) for elem in mac]) + ">>\n"
    print "mac: " + base64.b64encode(mac) + "\n"
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


def newLocation():
    """ Create a new, fake location
    """
    global accuracy
    accuracy = accuracy - random.randint(0, 300)
    if (random.randint(0, 1000) == 42):
        accuracy = random.randint(1000, 50000)
    utc = int(time.time())
    lat = 37.3866 + geoWalk()
    lon = -122.0608 + geoWalk()
    if (accuracy < 10):
        accuracy = 10
    return {"t": {"ok": True, "la": lat, "lo": lon,
        "ti": utc, "acc": accuracy, "has_passcode": True}}


def getConfig(argv):
    """ Read in the config file
    """
    configFile = "config.ini"
    try:
        opts, args = getopt.getopt(argv, "c:", ["config="])
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in ("-c", "--config"):
            configFile = a
    config = ConfigParser.ConfigParser()
    print "Reading... %s\n" % configFile
    config.read(configFile)
    return config


def registerNew(config, cred):
    """ Register a new fake device
    """
    tmpl = config.get("urls", "reg")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"))
    assertion = config.get("main", "assertion")
    # divy up based on scheme.
    # New Assertion?
    if (True):
        regObj = {"assert": assertion,
                  "pushurl": "http://example.com",
                  "deviceid": "deadbeef00000000decafbad00000000"}
        # no HAWK
        reply = send(trg, regObj, {})
    else:
        pdb.set_trace()
        # Repeating here, because live tests use different values
        regObj = {"pushurl": "http://example.com",
                  "deviceid": "deadbeef00000000decafbad00000000"}
        # with HAWK
        reply = send(trg, regObj, cred)
    cred = reply.json()
    print "### Returned Credentials: "
    pprint(cred)
    #listener("deadbeef00000000decafbad00000000")
    return sendCmd(config, cred, newLocation()), cred


def send(urlStr, data, cred, method="POST"):
    """ Generic function that wraps data and sends it to the server
    """
    session = requests.Session()
    headers = {"content-type": "application/json"}
    datas = json.dumps(data)
    if cred.get("secret") is not None:
        # generate HAWK auth header
        bodyHash = genHash(datas, "application/json")
        ts, nonce, mac = genHawkSignature(method, urlStr, bodyHash, "",
                                          cred.get("secret"))
        header = Template('Hawk id="$id", ts="$ts", ' +
                          'nonce="$nonce", ext="$extra", ' +
                          'hash="$bhash", mac="$mac"'
                          ).safe_substitute(id=cred.get("deviceid"),
                                            extra="",
                                            bhash=bodyHash,
                                            ts=ts, nonce=nonce, mac=mac)
        #print "Header: %s\n" % (header)
        headers["Authorization"] = header

    req = requests.Request(method,
                           urlStr,
                           data=json.dumps(data),
                           headers=headers)
    prepped = req.prepare()
    response = session.send(prepped, timeout=2)
    if response.status_code != requests.codes.ok:
        pdb.set_trace()
        print "Response Not OK"
        requests.Response.raise_for_status()
    if response.headers.get("Authorization") is not None:
        if checkHawk(response, cred.get("secret")) is False:
            pdb.set_trace()
            print "HAWK Header failed"
    return response


def processCmd(config, cred, cmd):
    """ Process the command like a client.
        Or a cat. Which it kinda does now.
    """
    if cmd is None:
        return
    #TODO: you can insert various responses to commands here
    # or just eat them like I'm doing right now.
    print "Command Recv'd: %s" % cmd
    reply = {}
    obj = cmd.json()
    if obj != {}:
        if 'r' in obj:
            print "Ringing for %s seconds" % obj['r']['d']
            reply = {"r": {"ok": True}}
        elif 'l' in obj:
            print "Locking device with code %s" % obj['l']['c']
            if 'm' in obj['l']:
                print "with message \"%s\"" % obj['l']['m']
            reply = {"l": {"ok": True}}
        elif 'e' in obj:
            print "Erasing device..."
            reply = {"e": {"ok": True}}
        elif 't' in obj:
            print "Tracking device for %s seconds" % obj['t']['d']
            reply = newLocation()
        else:
            print "Unknown command"
            pprint(obj)
            return
    # ack the command
    if reply != {}:
        return sendCmd(config, cred, reply)
    print "\n============\n\n"
    return None


def sendCmd(config, cred, cmd):
    """ Shorthand method to send a command to the server.
    """
    print "Sending Cmd %s\n" % json.dumps(cmd)
    if cmd == {}:
        return
    tmpl = config.get("urls", "cmd")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"),
        devid=cred.get("deviceid", "test1"))
    return send(trg, cmd, cred)


def main(argv):
    global accuracy
    accuracy = 5000
    config = getConfig(argv)
    cmd = {}
    try:
        creds = config.get("main", "cred")
    except Exception:
        creds = None
    if creds is None:
        cred = {}
    else:
        cred = json.loads(creds)
    # register a new device
    print "Registering client... \n"
    cmd, cred = registerNew(config, cred)
    #while cmd is not None:
    while True:
        # Burn through the command queue.
        print "Processing commands...\n"
        cmd = processCmd(config, cred, cmd)
        #import pdb; pdb.set_trace()
        #print "!!! Sending reregister... \n"
        #time.sleep(1)
        cmd = sendCmd(config, cred, newLocation())
        #cmd, cred = registerNew(config, cred)

    # Send a fake statement saying that the client has no passcode.
    response = sendCmd(config, cred, {'has_passcode': False})
    if response is not None:
        print(response.text)
    print "done"


if __name__ == "__main__":
    main(sys.argv[1:])
