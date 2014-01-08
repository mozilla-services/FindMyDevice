#!/usr/bin/python

import time
import ConfigParser
import json
import random
import httplib
import urlparse
from pprint import pprint
import getopt
import sys
import os
import hmac
import hashlib
from string import Template


def genHawkSignature(method, url, extra, secret, now=None, nonce=None):
    path = url.path
    host = url.hostname
    port = url.port
    if nonce is None:
        nonce = os.urandom(5).encode("hex")
    if now is None:
        now = int(time.time())
    marshalStr = "%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n%s" % (
        "hawk.1.header",
        now,
        nonce,
        method,
        path,
        host,
        port,
        extra)
    return now, nonce, hmac.new(secret.encode("utf-8"),
                                marshalStr.encode("utf-8"),
                                digestmod=hashlib.sha256).hexdigest()


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
    ts, n, mac = genHawkSignature(method, url, extra, secret,
                                  hawk["ts"], hawk["nonce"])
    return mac == hawk["mac"]


def geoWalk():
    return (random.randint(0, 99999) * 0.00001)


def newLocation():
    utc = int(time.time())
    lat = 37 + geoWalk()
    lon = -122 + geoWalk()
    return {"t": {"la": lat, "lo": lon, "ti": utc, "ke": True}}


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
    config.read(configFile)
    return config


def registerNew(config):
    tmpl = config.get("urls", "reg")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"))
    # divy up based on scheme.
    regObj = {"assert": "test",
              "pushurl": "http://example.com",
              "deviceid": "test1",
              "accepts": ["t", "r", "e"]}
    reply = send(trg, regObj)
    pprint(reply)
    glob = reply
    return sendTrack(config), glob


def send(urlStr, data, glob, method="POST"):
    url = urlparse.urlparse(urlStr)
    http = httplib.HTTPConnection(url.netloc)
    headers = {}
    datas = json.dumps(data)
    if glob.get("secret") is not None:
        # generate HAWK auth header
        h = hashlib.sha256()
        h.update(datas)
        extra = h.hexdigest()
        ts, nonce, mac = genHawkSignature(method, url, extra,
                                          glob.get("secret"))
        header = Template('Hawk id="$id", ts="$ts", ' +
                          'nonce="$nonce", ext="$extra", mac="$mac"'
                          ).safe_substitute(id=glob.get("id"),
                                            extra=extra,
                                            ts=ts, nonce=nonce, mac=mac)
        headers["Authorization"] = header
    http.request(method, url.path, datas, headers)
    response = http.getresponse()
    if response.status != 200:
        # TODO do stuff.
        import pdb; pdb.set_trace()
    rbody = response.read()
    if len(rbody) > 0:
        body = json.loads(rbody)
        pprint(body)
        return body
    return None


def processCmd(config, cmd, glob):
    print "Command..."
    pprint(cmd)
    print "\n============\n\n"


def sendTrack(config, glob):
    # get fake track info
    print "Sending track info\n"
    tmpl = config.get("urls", "cmd")
    trg = Template(tmpl).safe_substitute(
        scheme=config.get("main", "scheme"),
        host=config.get("main", "host"),
        id=glob.get("id"))
    return send(trg, newLocation(), glob)
    print "\n============\n\n"


def main(argv, glob={}):
    config = getConfig(argv)
    cmd = {}
    # register a new device
    if 'id' not in glob:
        print "Registering as new client... \n"
        cmd, glob = registerNew(config)
    else:
        print "Already registered...\n"
        cmd = sendTrack(config, glob)
    while cmd is not None:
        print "Processing commands...\n"
        cmd = processCmd(config, cmd, glob)


if __name__ == "__main__":
    glob = {u'secret': u'QAXUbiz2aRYTHrL951OwrA==', u'id': u'test1'}
    main(sys.argv[1:], glob)
