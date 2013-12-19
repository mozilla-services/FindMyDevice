package wmf

import (
    "mozilla.org/util"
    "crypto/rand"
    "encoding/base64"
    "crypto/sha256"
    "crypto/hmac"
    "errors"
    "net/http"
    "fmt"
    "strings"
    "strconv"
    "time"

)

// Stubbed for now.
// minimal HAWK for now (e.g. no bewit because IAGNI)

var ErrNoAuth = errors.New("No Authorization Header")
var ErrNotHawkAuth = errors.New("Not a Hawk Authorization Header")
var ErrInvalidSignature = errors.New("Header does not match signature")

var header = "hawk.1.header"
var marshal = "%s\n%s\n%s\n%s\n%s\n%s\n%d\n\n"

type Hawk struct {
    logger *util.HekaLogger
    header string
    Id string
    Time string
    Nonce string
    Method string
    Path string
    Host string
    Port string
    Extra string
    signature string
}

func GenNonce(l int) (string) {
    // generate a nonce.
    if l == 0 {
        l = 6
    }
    ret := make([]byte, l)
    rand.Read(ret)
    return base64.StdEncoding.EncodeToString(ret)
}

func (self *Hawk) AsHeader(req *http.Request, id, extra, secret, signature string ) (string){
    if signature == "" {
        signature, _ = self.GenerateSignature(req, extra, secret)
    }
    return fmt.Sprintf("Hawk id=\"%s\", ts=\"%s\", nonce=\"%s\" ext=\"%s\", mac=\"%s\"",
        id,
        self.Time,
        self.Nonce,
        self.Extra,
        signature)
}

func getFullPath(req *http.Request) (path string) {
    path = req.URL.Path
    if len(req.URL.RawQuery) > 0 {
        path = path + "?" + req.URL.RawQuery
    }
    if len(req.URL.Fragment) > 0 {
        path = path + "#" + req.URL.Fragment
    }
    return path
}

func getHostPort(req *http.Request) (host,port string) {
    elements := strings.Split(req.Host, ":")
    host = elements[0]
    switch {
        case len(elements) > 1:
            port = elements[1]
        case req.URL.Scheme == "https":
            port = "443"
        default:
            port = "80"
    }
    return host, port
}

func (self *Hawk) GenerateSignature(req *http.Request, extra, secret string) (sig string,err error) {
    // create path
    if self.Path == "" {
        self.Path = getFullPath(req)
    }
    // figure out port
    if self.Host == "" {
        self.Host, self.Port = getHostPort(req)
    }
    if self.Nonce == "" {
        self.Nonce = GenNonce(6)
    }
    if self.Time == "" {
        self.Time = strconv.FormatInt(time.Now().UTC().Unix(), 10)
    }
    marshalStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n%s",
        self.header,
        self.Time,
        self.Nonce,
        self.Method,
        self.Path,
        self.Host,
        self.Port,
        extra)

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(marshalStr))
    return base64.StdEncoding.EncodeToString(mac.Sum(nil)), err
}

func ParseHawkAuthHeader(req *http.Request, logger *util.HekaLogger) (ret *Hawk, signature string, err error) {

    auth := req.Header.Get("Authorization")
    if auth == "" {
        return nil, "", ErrNoAuth
    }
    if strings.ToLower(auth[:4]) != "hawk"{
        return nil, "", ErrNotHawkAuth
    }
    elements := strings.Split(auth[5:],", ")
    ret = &Hawk{}
    for _,element := range elements {
        kv := strings.Split(element, "=")
        if len(kv) < 2 {
            continue
        }
        val := strings.Trim(kv[1], "\"")
        switch strings.ToLower(kv[0]) {
        case "id":
            ret.Id = val
        case "ts":
            ret.Time = val
        case "nonce":
            ret.Nonce = val
        case "ext":
            ret.Extra = val
        case "mac":
            signature = val
        }
    }
    ret.Path = getFullPath(req)
    ret.Host, ret.Port = getHostPort(req)
    return ret, signature, err
}
