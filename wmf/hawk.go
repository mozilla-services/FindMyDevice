package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/mozilla-services/FindMyDevice/util"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrNoAuth = errors.New("No Authorization Header")
var ErrNotHawkAuth = errors.New("Not a Hawk Authorization Header")
var ErrInvalidSignature = errors.New("Header does not match signature")
var ErrReplayedNonce = errors.New("Nonce detected. Replay?")

// minimal HAWK for now (e.g. no bewit because IAGNI)
type Hawk struct {
	logger    util.Logger
	config    *util.MzConfig
	header    string
	Id        string
	Time      string
	Nonce     string
	Method    string
	Path      string
	Host      string
	Port      string
	Extra     string
	Hash      string
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

// Clear the stickier bits
func (self *Hawk) Clear() {
	self.Hash = ""
	self.Signature = ""
	self.Nonce = ""
	self.Time = ""
	self.Path = ""
	self.Port = ""
}

type nonceCache struct {
	sync.RWMutex
	order []string
	hash  map[string]struct{}
}

var HawkNonces *nonceCache

func init() {
	count := 100

	HawkNonces = &nonceCache{
		order: make([]string, count),
		hash:  make(map[string]struct{}),
	}
}

func (r *nonceCache) Contains(value string) bool {
	r.Lock()
	defer r.Unlock()
	_, ok := r.hash[value]
	return ok
}

func (r *nonceCache) Add(nonce string) bool {
	if r.Contains(nonce) {
		return false
	}
	r.Lock()
	defer r.Unlock()
	rl := len(r.order) - 1
	if r.order[rl] != "" {
		delete(r.hash, r.order[rl])
	}
	copy(r.order[1:], r.order[:rl])
	r.order[0] = nonce
	r.hash[nonce] = struct{}{}
	return true
}

// Return a Hawk Authorization header
func (self *Hawk) AsHeader(req *http.Request, id, body, extra, secret string) string {
	if self.Signature == "" {
		self.GenerateSignature(req, extra, body, secret)
	}
	if extra == "" && len(self.Extra) > 0 {
		extra = self.Extra
	}
	rep := fmt.Sprintf("Hawk id=\"%s\", ts=\"%s\", nonce=\"%s\", ext=\"%s\", hash=\"%s\", mac=\"%s\"",
		id,
		self.Time,
		self.Nonce,
		extra,
		self.Hash,
		self.Signature)
	return rep
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
func (self *Hawk) getHostPort(req *http.Request) (host, port string) {

	elements := strings.Split(req.Host, ":")
	host = elements[0]
	if self.config != nil {
		port = self.config.Get("hawk.port", "")
	}
	if port == "" {
		if len(elements) == 2 {
			port = elements[1]
		}
		if self.config.GetFlag("override_port") {
			switch {
			// because nginx proxies, don't take the :port at face value
			//case len(elements) > 1:
			//	port = elements[1]
			case req.URL.Scheme == "https":
				port = "443"
			default:
				port = "80"
			}
		}
	}
	return host, port
}

func (self *Hawk) genHash(req *http.Request, body string) (hash string) {
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}
	// Something is appending the chartype to the content. this can throw off
	// the hash generator.
	// Client creates mac using "application/json",
	// we get "application/json;charset=UTF8" which brings much sadness.
	contentType = (strings.Split(contentType, ";"))[0]
	nbody := strings.Replace(body, "\\", "\\\\", -1)
	nbody = strings.Replace(nbody, "\n", "\\n", -1)
	marshalStr := fmt.Sprintf("%s\n%s\n%s\n",
		"hawk.1.payload",
		contentType,
		nbody)
	sha := sha256.Sum256([]byte(marshalStr))
	hash = base64.StdEncoding.EncodeToString([]byte(sha[:32]))
	if self.config.GetFlag("hawk.show_hash") {
		self.logger.Debug("hawk", "genHash",
			util.Fields{"marshalStr": marshalStr,
				"hash": hash})
	}
	return hash

}

// Initialize self from request, extra and secret
/* Things to check:
 * Are all values being sent? (e.g. extra, time, secret)
 * Do the secrets match?
 * is the other format string formatted correctly? (two \n before extra, 0 after)
 */
func (self *Hawk) GenerateSignature(req *http.Request, extra, body, secret string) (err error) {
	// create path
	if self.Path == "" {
		self.Path = getFullPath(req)
	}
	// figure out port
	if self.Host == "" {
		self.Host, self.Port = self.getHostPort(req)
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
	if self.Hash == "" {
		self.Hash = self.genHash(req, body)
	}
	self.Extra = extra

	marshalStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		"hawk.1.header",
		self.Time,
		self.Nonce,
		strings.ToUpper(self.Method),
		self.Path,
		strings.ToLower(self.Host),
		self.Port,
		self.Hash,
		self.Extra)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(marshalStr))
	self.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if self.config.GetFlag("hawk.show_hash") {
		self.logger.Debug("hawk", "Marshal",
			util.Fields{"marshalStr": marshalStr,
				"secret": secret,
				"mac":    self.Signature})
	}
	return err
}

// Initialize self from the AuthHeader
func (self *Hawk) ParseAuthHeader(req *http.Request, logger util.Logger) (err error) {

	auth := req.Header.Get("Authorization")
	if auth == "" {
		return ErrNoAuth
	}
	if strings.ToLower(auth[:4]) != "hawk" {
		return ErrNotHawkAuth
	}
	elements := strings.Split(auth[5:], ", ")
	for _, element := range elements {
		kv := strings.SplitN(element, "=", 2)
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
			if !HawkNonces.Add(val) {
				return ErrReplayedNonce
			}
		case "ext":
			self.Extra = val
		case "hash":
			self.Hash = val
		case "mac":
			self.Signature = val
		}
	}
	self.Path = getFullPath(req)
	self.Method = strings.ToUpper(req.Method)
	self.Host, self.Port = self.getHostPort(req)
	if self.config.GetFlag("hawk.show_hash") {
		self.logger.Debug("hawk", "Parsed Header",
			util.Fields{"Time": self.Time,
				"Nonce":  self.Nonce,
				"Method": self.Method,
				"Path":   self.Path,
				"Host":   self.Host,
				"Port":   self.Port,
				"Extra":  self.Extra,
				"Hash":   self.Hash,
				"Sig":    self.Signature})
	}
	return err
}

// Compare a signature value against the generated Signature.
func (self *Hawk) Compare(sig string) bool {
	// This should probably decode to byte array and compare.
	return strings.TrimRight(sig, "=") == strings.TrimRight(self.Signature, "=")
}
