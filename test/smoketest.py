#!/usr/bin/python

from pprint import pprint
from string import Template
import ConfigParser
import base64
import getopt
import hashlib
import hmac
import httplib
import json
import os
import random
import sys
import time
import urlparse


def genHash(body, ctype="application/json"):
    if len(body) == 0:
        return ""
    marshalStr = "%s\n%s\n%s\n" % (
        "hawk.1.payload",
        ctype,
        body)
    bhash = base64.b64encode(hashlib.sha256(marshalStr).digest())
    #print "Hash:<<%s>>\nBHash:<<%s>>\n" % (marshalStr, bhash)
    return bhash


def genHawkSignature(method, url, bodyHash, extra, secret,
                     now=None, nonce=None, ctype="application/json"):
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
        method,
        path,
        host,
        port,
        bodyHash,
        extra)
    #print "Marshal Str: <<%s>>\nSecret: <<%s>>\n" % (marshalStr, secret)
    mac = hmac.new(secret.encode("utf-8"),
                   marshalStr.encode("utf-8"),
                   digestmod=hashlib.sha256).digest()
    #print "mac: <<" + ','.join([str(ord(elem)) for elem in mac]) + ">>\n"
    return now, nonce, base64.b64encode(mac)


def parseHawkHeader(header):
    result = {}
    if header[:4].lower != "hawk":
        return None
    elements = header[5:].split(", ")
    for elem in elements:
        bits = elem.split("=")
        result[bits[0]] = bits[1]
    return result


def checkHawk(method, url, extra, secret, header):
    hawk = parseHawkHeader(header)
    ts, n, mac = genHawkSignature(method, url, extra, hawk["hash"], secret,
                                  hawk["ts"], hawk["nonce"])
    # remove "white space
    return mac.replace('=', '') == hawk["mac"].replace('=', '')


def geoWalk():
    return (random.randint(0, 999) * 0.000001)


def newLocation():
    utc = int(time.time())
    lat = 37.3883 + geoWalk()
    lon = -122.0615 + geoWalk()
    return {"t": {"la": lat, "lo": lon, "ti": utc, "ha": True}}


def getConfig(argv):
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


def registerNew(config):
    tmpl = config.get("urls", "reg")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"))
    # divy up based on scheme.
    regObj = {"assert": "",
              "pushurl": "http://example.com",
              "deviceid": "test1"}
    reply = send(trg, regObj, {})
    pprint(reply)
    cred = reply
    return sendCmd(config, cred, newLocation()), cred


def send(urlStr, data, cred, method="POST"):
    url = urlparse.urlparse(urlStr)
    http = httplib.HTTPConnection(url.netloc)
    headers = {"Content-Type": "application/json"}
    datas = json.dumps(data)
    if cred.get("secret") is not None:
        # generate HAWK auth header
        bodyHash = genHash(datas, "application/json")
        ts, nonce, mac = genHawkSignature(method, url, bodyHash, "",
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
    import pdb;pdb.set_trace()
    print "Sending %s\n" % (url.path)
    http.request(method, url.path, datas, headers)
    response = http.getresponse()
    if response.status != 200:
        # TODO do stuff.
        import pdb; pdb.set_trace()
        print "Crap."
        return None
    rbody = response.read()
    if len(rbody) > 0:
        body = json.loads(rbody)
        pprint(body)
        return body
    return None


def processCmd(config, cmd, cred):
    print "Command Recv'd..."
    pprint(cmd)
    print "\n============\n\n"


def sendCmd(config, cred, cmd):
    print "Sending Cmd %s\n" % json.dumps(cmd)
    tmpl = config.get("urls", "cmd")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"),
        id=cred.get("deviceid", "test1"))
    return send(trg, cmd, cred)
    print "\n============\n\n"


def main(argv):
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
    cmd, cred = registerNew(config)
    while cmd is not None:
        print "Processing commands...\n"
        cmd = processCmd(config, cmd, cred)
    sendCmd(config, cred, {'has_passcode': False})
#    sendCmd(config, cred, {'l': {'ok': True}, 'has_passcode': True})

if __name__ == "__main__":
    main(sys.argv[1:])
