package wmf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mozilla.org/util"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// minimal HAWK for now (e.g. no bewit because IAGNI)

var ErrNoAuth = errors.New("No Authorization Header")
var ErrNotHawkAuth = errors.New("Not a Hawk Authorization Header")
var ErrInvalidSignature = errors.New("Header does not match signature")

type Hawk struct {
	logger    *util.HekaLogger
	header    string
	Id        string
	Time      string
	Nonce     string
	Method    string
	Path      string
	Host      string
	Port      string
	Extra     string
	Signature string
}

// Generate a nonce l bytes long (if l == 0, 6 bytes)
func GenNonce(l int) string {
	if l == 0 {
		l = 6
	}
	ret := make([]byte, l)
	rand.Read(ret)
	return base64.StdEncoding.EncodeToString(ret)
}

// Return a Hawk Authorization header
func (self *Hawk) AsHeader(req *http.Request, id, extra, secret string) string {
	if self.Signature == "" {
		self.GenerateSignature(req, extra, secret)
	}
	return fmt.Sprintf("Hawk id=\"%s\", ts=\"%s\", nonce=\"%s\" ext=\"%s\", mac=\"%s\"",
		id,
		self.Time,
		self.Nonce,
		self.Extra,
		self.Signature)
}

// get the full path + fragment from the request
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

// get the host and port from the request
func getHostPort(req *http.Request) (host, port string) {
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

// Initialize self from request, extra and secret
/* Things to check:
 * Are all values being sent? (e.g. extra, time, secret)
 * Do the secrets match?
 * is the other format string formatted correctly? (two \n before extra, 0 after)
 */
func (self *Hawk) GenerateSignature(req *http.Request, extra, secret string) (err error) {
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
	if self.Method == "" {
		self.Method = strings.ToUpper(req.Method)
	}
	marshalStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n%s",
		"hawk.1.header",
		self.Time,
		self.Nonce,
		self.Method,
		self.Path,
		self.Host,
		self.Port,
		extra)

	self.logger.Debug("hawk", "Marshal",
		util.Fields{"marshalStr": marshalStr,
			"secret": secret})
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(marshalStr))
	self.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return err
}

// Initialize self from the AuthHeader
func (self *Hawk) ParseAuthHeader(req *http.Request, logger *util.HekaLogger) (err error) {

	auth := req.Header.Get("Authorization")
	if auth == "" {
		return ErrNoAuth
	}
	if strings.ToLower(auth[:4]) != "hawk" {
		return ErrNotHawkAuth
	}
	elements := strings.Split(auth[5:], ", ")
	for _, element := range elements {
		kv := strings.Split(element, "=")
		if len(kv) < 2 {
			continue
		}
		val := strings.Trim(kv[1], "\"")
		switch strings.ToLower(kv[0]) {
		case "id":
			self.Id = val
		case "ts":
			self.Time = val
		case "nonce":
			self.Nonce = val
		case "ext":
			self.Extra = val
		case "mac":
			self.Signature = val
		}
	}
	self.Path = getFullPath(req)
	self.Host, self.Port = getHostPort(req)
	return err
}

// Compare a signature value against the generated Signature.
func (self *Hawk) Compare(sig string) bool {
	// This should probably decode to byte array and compare.
	return strings.TrimRight(sig, "=") == strings.TrimRight(self.Signature, "=")
}
