package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"code.google.com/p/go.net/websocket"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"

	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	// "io/ioutil"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// base handler for REST and Socket calls.
type Handler struct {
	config  *util.MzConfig
	logger  *util.HekaLogger
	metrics *util.Metrics
	devId   string
	logCat  string
	accepts []string
	hawk    *Hawk
	store   *storage.Storage
	maxCli  int64
}

const (
	SESSION_NAME     = "user"
	SESSION_LOGIN    = "login"
	OAUTH_ENDPOINT   = "https://oauth.accounts.firefox.com"
	CONTENT_ENDPOINT = "https://accounts.firefox.com"
	SESSION_USERID   = "userid"
	SESSION_EMAIL    = "email"
	SESSION_TOKEN    = "token"
	SESSION_DEVICEID = "deviceid"
)

// Generic reply structure (useful for JSON responses)
type replyType map[string]interface{}

// Each session contains a UserID and a DeviceID
type sessionInfoStruct struct {
	UserId      string
	DeviceId    string
	Email       string
	AccessToken string
}

type initDataStruct struct {
	ProductName string
	UserId      string
	MapKey      string
	DeviceList  []storage.DeviceList
	Device      *storage.Device
	Host        map[string]string
}

// Map of clientIDs to socket handlers

//Errors
var (
	ErrInvalidReply  = errors.New("Invalid Command Response")
	ErrAuthorization = errors.New("Needs Authorization")
	ErrNoUser        = errors.New("No User")
	ErrOauth         = errors.New("OAuth Error")
	ErrNoClient      = errors.New("No Client for Update")
	ErrTooManyClient = errors.New("Too Many Clients for device")
)

// package globals
var (
	muClient sync.RWMutex
	// using a map of maps here because it's less hassle than iterating
	// over a list. Need to investigate if there's significant memory loss
	Clients      = make(map[string]map[string]*WWS)
	sessionStore *sessions.CookieStore
)

// Client Mapping functions
// Add a new trackable client.
func addClient(id, instance string, sock *WWS, maxInstances int64) error {
	fmt.Printf("+++ Adding client for %s:%s\n", id, instance)
	defer muClient.Unlock()
	muClient.Lock()
	if clients, ok := Clients[id]; ok {
		if maxInstances > 0 && len(clients) > int(maxInstances) {
			return ErrTooManyClient
		}
		if _, ok := clients[instance]; !ok {
			Clients[id][instance] = sock
			return nil
		} else {
			fmt.Printf("+++ !!! Instance clash %s::%s\n", id, instance)
			return ErrTooManyClient
		}
	} else {
		Clients[id] = make(map[string]*WWS)
		Clients[id][instance] = sock
	}
	return nil
}

// remove a trackable client, returns if tracking should stop
func rmClient(id, instance string) (bool, error) {
	defer muClient.Unlock()
	muClient.Lock()
	if clients, ok := Clients[id]; ok {
		// remove the instance
		if cli, ok := clients[instance]; ok {
			fmt.Printf("--- removing instance %s::%s\n", id, instance)
			// Forcing client connection closed
			if cli.Socket.IsClientConn() {
				cli.Socket.Close()
			}
			delete(clients, instance)
			if len(clients) == 0 {
				fmt.Printf("--- Purging instances for %s\n", id)
				delete(Clients, id)
				return true, nil
			} else {
				Clients[id] = clients
			}
			return false, nil
		}
		fmt.Printf("--- !!! No instance of %s::%s\n", id, instance)
		return true, ErrNoClient
	}
	fmt.Printf("--- !!! No clients for %s!\n", id)
	return true, ErrNoClient
}

//Handler private functions

// SUPER FAKE DO NOT EVER USE IN PRODUCTION FOR DEBUGGING ONLY!
// Extract the user info from the assertion WITHOUT VERIFICATIONS

func (self *Handler) extractFromAssertion(assertion string) (userid, email string, err error) {
	var ErrInvalidAssertion = errors.New("Invalid assertion")
	bits := strings.Split(assertion, ".")
	if len(bits) < 2 {
		self.logger.Error(self.logCat, "Invalid assertion",
			util.Fields{"assertion": assertion})
		return "", "", ErrInvalidAssertion
	}
	data := bits[1]
	// pad to byte boundry
	data = data + "===="[:len(data)%4]
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		self.logger.Error(self.logCat, "Could not decode assertion",
			util.Fields{"assertion frame": data})
		return "", "", ErrInvalidAssertion
	}
	asrt := make(replyType)
	err = json.Unmarshal(decoded, &asrt)
	if err != nil {
		self.logger.Error(self.logCat, "Could not unmarshal",
			util.Fields{"error": err.Error()})
		return "", "", err
	}
	// Normally, the UserID would be provided from FxA.
	// since FxA is currently unavailable for desktop, we're going
	// to need a value here, thus the insecure Id generation.
	// Obviously:
	// ******** DO NOT ENABLE auth.disabled FLAG IN PRODUCTION!! ******
	if e, ok := asrt["fxa-verifiedEmail"]; ok {
		email = e.(string)
	} else {
		email = asrt["principal"].(map[string]interface{})["email"].(string)
	}
	userid = self.genHash(email)
	self.logger.Debug(self.logCat, "Extracted credentials",
		util.Fields{"userId": userid, "email": email})
	return userid, email, nil
}

// Somewhat of a hack, extract the audience from the assertion. This is
// because some versions of the client do not specify the correct audience
// and a mis-match causes the assertion to fail.
func (self *Handler) extractAudience(assertion string) (audience string) {
	bits := strings.Split(assertion, ".")
	// Classic? persona has 3 chunks, modified has 5.
	if len(bits) == 5 {
		if data, err := base64.StdEncoding.DecodeString(bits[3] + "===="[:len(bits[3])%4]); err == nil {
			dj := make(replyType)
			if err = json.Unmarshal(data, &dj); err == nil {
				if v, ok := dj["audience"]; ok {
					// fxa
					return v.(string)
				} else if v, ok := dj["aud"]; ok {
					// persona
					return v.(string)
				}
			}
		}
	}
	return ""
}

// verify a Persona assertion using the config values
// part of Handler for config & logging reasons
func (self *Handler) verifyPersonaAssertion(assertion string) (userid, email string, err error) {
	var ok bool
	var audience string

	if assLen := len(assertion); assLen != len(strings.Map(assertionFilter, assertion)) {
		self.logger.Error(self.logCat, "Assertion contains invalid characters.",
			util.Fields{"assertion": assertion})
		return "", "", ErrAuthorization
	}

	// ******** DO NOT ENABLE auth.disabled FLAG IN PRODUCTION!! ******
	if self.config.GetFlag("auth.disabled") {
		self.logger.Warn(self.logCat, "!!! Skipping validation...", nil)
		if len(assertion) == 0 {
			return "user1", "user@example.com", nil
		}
		// Time to UberFake! THIS IS VERY DANGEROUS!
		self.logger.Warn(self.logCat,
			"!!! Using Assertion Without Validation",
			nil)
		return self.extractFromAssertion(assertion)
	}
	// pull the audience out of the assertion, if it's present.
	if self.config.GetFlag("auth.audience_from_assertion") {
		audience = self.extractAudience(assertion)
	}
	if audience == "" {
		audience = self.config.Get("persona.audience",
			"http://localhost:8080")
	}
	// Better verify for realz
	validatorURL := self.config.Get("persona.verifier",
		"https://verifier.login.persona.org/v2")
	body, err := json.Marshal(
		util.Fields{"assertion": assertion,
			"audience": audience})
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not marshal assertion",
			util.Fields{"error": err.Error()})
		return "", "", ErrAuthorization
	}
	if self.config.GetFlag("auth.show_assertion") {
		fmt.Printf("### Validating Assertion:\n %s\n", body)
	}
	req, err := http.NewRequest("POST", validatorURL, bytes.NewReader(body))
	if err != nil {
		self.logger.Error(self.logCat, "Could not POST assertion",
			util.Fields{"error": err.Error()})
		return "", "", err
	}
	req.Header.Add("Content-Type", "application/json")
	cli := http.Client{}
	res, err := cli.Do(req)
	if err != nil {
		self.logger.Error(self.logCat, "Persona verification failed",
			util.Fields{"error": err.Error()})
		return "", "", ErrAuthorization
	}

	// Handle the verifier response
	buffer, raw, err := parseBody(res.Body)
	if isOk, ok := buffer["status"]; !ok || isOk != "okay" {
		var errStr string
		if err != nil {
			errStr = err.Error()
		} else if _, ok = buffer["reason"]; ok {
			errStr = buffer["reason"].(string)
		}
		self.logger.Error(self.logCat, "Persona Auth Failed",
			util.Fields{"error": errStr,
				"body": raw})
		return "", "", ErrAuthorization
	}

	// extract the email
	if idp, ok := buffer["idpClaims"]; ok {
		if fxe, ok := idp.(map[string]interface{})["fxa-verifiedEmail"]; ok {
			email = fxe.(string)
			userid = self.genHash(email)
			return userid, email, nil
		}
	}

	if email, ok = buffer["email"].(string); !ok {
		self.logger.Error(self.logCat, "No email found in assertion",
			util.Fields{"assertion": fmt.Sprintf("%+v", buffer)})
		return "", "", ErrAuthorization
	}
	// and the userid, generating one if need be.
	if _, ok = buffer["userid"].(string); !ok {
		userid = self.genHash(email)
	}
	return userid, email, nil
}

func (self *Handler) verifyFxAAssertion(assertion string) (userid, email string, err error) {
	if assLen := len(assertion); assLen != len(strings.Map(assertionFilter, assertion)) {
		self.logger.Error(self.logCat, "Assertion contains invalid characters.",
			util.Fields{"assertion": assertion})
		return "", "", ErrAuthorization
	}

	// ******** DO NOT ENABLE auth.disabled FLAG IN PRODUCTION!! ******
	if self.config.GetFlag("auth.disabled") {
		self.logger.Warn(self.logCat, "!!! Skipping validation...", nil)
		return self.extractFromAssertion(assertion)

	}
	cli := http.Client{}
	validatorUrl := self.config.Get("fxa.verifier",
		"https://oauth.accounts.firefox.com/authorization")
	// fmt.Printf("### Sending to %s\n", validatorUrl)
	args := make(map[string]string)
	args["client_id"] = self.config.Get("fxa.client_id", "invalid")
	args["assertion"] = assertion
	if self.config.GetFlag("auth.audience_from_assertion") {
		args["audience"] = self.extractAudience(assertion)
		self.logger.Info(self.logCat, "Extracted Audience",
			util.Fields{"audience": args["audience"]})
	}
	if self.config.GetFlag("auth.trim_audience") {
		audUrl, err := url.Parse(args["audience"])
		if err != nil {
			self.logger.Warn(self.logCat, "Could not parse Audience",
				util.Fields{"error": err.Error(),
					"audience": args["audience"]})
		} else {
			args["audience"] = fmt.Sprintf("%s://%s/", audUrl.Scheme,
				audUrl.Host)
		}
	}
	if args["audience"] == "" {
		args["audience"] = self.config.Get("fxa.audience",
			"https://oauth.accounts.firefox.com/v1")
	}
	// State is a nonce useful for validation callbacks.
	// Since we're not calling back, it's not necessary to
	// check if the caller matches the recipient.
	args["state"], _ = util.GenUUID4()

	argsj, err := json.Marshal(args)
	if err != nil {
		self.logger.Error(self.logCat, "Could not marshal args",
			util.Fields{"error": err.Error()})
		return "", "", err
	}
	if self.config.GetFlag("auth.show_assertion") {
		fmt.Printf("### Validating Assertion:\n %s\n", argsj)
	}
	// Send the assertion to the validator
	req, err := http.NewRequest("POST", validatorUrl, bytes.NewReader(argsj))
	if err != nil {
		self.logger.Error(self.logCat, "Could not POST verify assertion",
			util.Fields{"error": err.Error()})
		return "", "", err
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		self.logger.Error(self.logCat, "FxA verification failed",
			util.Fields{"error": err.Error()})
		return "", "", err
	}
	buff, raw, err := parseBody(res.Body)
	if err != nil {
		return "", "", err
	}
	if code, ok := buff["code"]; ok && code.(float64) > 299.0 {
		self.logger.Error(self.logCat, "FxA verification failed auth",
			util.Fields{"code": strconv.FormatInt(int64(code.(float64)), 10),
				"error": buff["error"].(string),
				"body":  raw})
		return "", "", err
	}
	if status, ok := buff["status"]; ok {
		if status == "failure" {
			self.logger.Error(self.logCat, "FxA verification failed",
				util.Fields{"error": buff["reason"].(string)})
			return "", "", ErrOauth
		}
	}
	// the response has either been a redirect or a validated assertion.
	// fun times, fun times...
	if idp, ok := buff["idpClaims"]; ok {
		if email, ok := idp.(map[string]interface{})["fxa-verifiedEmail"]; ok {
			return self.genHash(email.(string)), email.(string), nil
		}
	}
	// get the "redirect" url. We're not going to redirect, just get the code.
	if redir, ok := buff["redirect"]; !ok {
		fmt.Printf("### Redirect: %s\n", raw)
		self.logger.Error(self.logCat, "FxA verification did not return redirect",
			nil)
		return "", "", err
	} else {
		if vurl, err := url.Parse(redir.(string)); err != nil {
			self.logger.Error(self.logCat, "FxA redirect url invalid",
				util.Fields{"error": err.Error(), "url": redir.(string)})
			return "", "", err
		} else {
			code := vurl.Query().Get("code")
			if len(code) == 0 {
				self.logger.Error(self.logCat, "FxA code not present",
					util.Fields{"url": redir.(string)})
				return "", "", ErrOauth
			}
			//Convert code to access token.
			accessToken, err := self.getAccessToken(code)
			if err != nil {
				return "", "", ErrOauth
			}
			email, err := self.getUserEmail(accessToken)
			if err != nil {
				return "", "", ErrOauth
			}
			// fmt.Printf("### Verified FxA assertion: %s, %s\n", accessToken, email)
			return self.genHash(email), email, nil
		}
	}
}

func (self *Handler) clearSession(sess *sessions.Session) (err error) {
	if sess == nil {
		return
	}
	delete(sess.Values, SESSION_USERID)
	delete(sess.Values, SESSION_DEVICEID)
	delete(sess.Values, SESSION_EMAIL)
	delete(sess.Values, SESSION_TOKEN)
	return
}

// Get the old index page data block
func (self *Handler) initData(resp http.ResponseWriter, req *http.Request, sessionInfo *sessionInfoStruct) (data *initDataStruct, err error) {
	/* Handle a user login to the web UI
	 */
	data = &initDataStruct{}
	self.logCat = "handler:initData"

	store := self.store

	// Get this from the config file?
	data.ProductName = self.config.Get("productname", "Find My Device")

	data.MapKey = self.config.Get("mapbox.key", "")

	// host information (for websocket callback)
	data.Host = make(map[string]string)
	// TODO: transition away from old config name
	data.Host["Hostname"] = self.config.Get("ws.hostname",
		self.config.Get("ws_hostname", "localhost"))

	// get the cached session info (if present)
	// will also resolve assertions and other bits to get user and dev info.
	if sessionInfo != nil {
		// we have user info, use it.
		data.UserId = sessionInfo.UserId
		if sessionInfo.DeviceId == "" {
			sessionInfo.DeviceId = getDevFromUrl(req.URL)
		}
		if sessionInfo.DeviceId == "" {
			data.DeviceList, err = store.GetDevicesForUser(data.UserId)
			if err != nil {
				self.logger.Error(self.logCat, "Could not get user devices",
					util.Fields{"error": err.Error(),
						"user": data.UserId})
				return nil, err
			}
		}
		if sessionInfo.DeviceId != "" {
			data.Device, err = store.GetDeviceInfo(sessionInfo.DeviceId)
			if err != nil {
				self.logger.Error(self.logCat, "Could not get device info",
					util.Fields{"error": err.Error(),
						"deviceid": sessionInfo.DeviceId})
				return nil, err
			}
			data.Device.PreviousPositions, err = store.GetPositions(sessionInfo.DeviceId)
			if err != nil {
				self.logger.Error(self.logCat,
					"Could not get device's position information",
					util.Fields{"error": err.Error(),
						"userId":   data.UserId,
						"email":    sessionInfo.Email,
						"deviceId": sessionInfo.DeviceId})
				return nil, err
			}
		}
	}
	return data, nil
}

// get the user id from the session, or the assertion.
func (self *Handler) getUser(resp http.ResponseWriter, req *http.Request) (userid, email string, err error) {

	var session *sessions.Session

	// because oauth may not always be present.
	if em := self.config.Get("auth.force_user", ""); len(em) > 0 {
		return self.genHash(em), em, nil
	}

	session, err = sessionStore.Get(req, SESSION_NAME)
	// fmt.Printf("### Your session is: %+v\n", session.Values)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open session",
			util.Fields{"error": err.Error()})
		// delete the current, invalid session?
		return "", "", err
	}
	if session != nil {
		// fmt.Printf("### Got session: %+v\n", session)
		var ret = false
		if ru, ok := session.Values[SESSION_EMAIL]; ok {
			switch ru.(type) {
			case string:
				email = ru.(string)
				userid = self.genHash(email)
				ret = true
			default:
				email = ""
			}
		}
		if ruid, ok := session.Values[SESSION_USERID]; ok {
			switch ruid.(type) {
			case string:
				userid = ruid.(string)
				ret = true
			default:
				userid = ""
			}
		}
		// return the contents of the session.
		if ret {
			self.logger.Info(self.logCat, "::Got User::",
				util.Fields{"source": "session",
					"userId": userid,
					"email":  email})
			return userid, email, nil
		}
	}
	// Nothing in the session,
	var auth string
	if auth = req.FormValue("assertion"); auth != "" {
		if self.config.GetFlag("auth.persona") {
			userid, email, err = self.verifyPersonaAssertion(auth)
		} else {
			userid, email, err = self.verifyFxAAssertion(auth)
		}
	}
	if err != nil {
		// error logged in verify
		return "", "", ErrAuthorization
	}
	if userid == "" && email != "" {
		userid = self.genHash(email)
	}
	self.logger.Info(self.logCat, "::Got User::",
		util.Fields{"source": "assertion",
			"userId": userid,
			"email":  email})
	return userid, email, nil
}

// set the user info into the session
func (self *Handler) getSessionInfo(resp http.ResponseWriter, req *http.Request, session *sessions.Session) (info *sessionInfoStruct, err error) {
	var userid string
	var email string
	var accessToken string

	dev := getDevFromUrl(req.URL)
	userid, email, err = self.getUser(resp, req)
	if err != nil {
		return nil, err
	}
	if userid == "" {
		if email != "" {
			userid = self.genHash(email)
		} else {
			// No userid? No session.
			return nil, ErrNoUser
		}
	}
	if token, ok := session.Values[SESSION_TOKEN]; ok {
		accessToken = token.(string)
	}
	info = &sessionInfoStruct{
		UserId:      userid,
		Email:       email,
		DeviceId:    dev,
		AccessToken: accessToken}
	return info, nil
}

func (self *Handler) stopTracking(devId string, store *storage.Storage) (err error) {
	noTrack := storage.Unstructured{"t": replyType{"d": 0}}
	jnt, err := json.Marshal(noTrack)
	if err != nil {
		self.logger.Warn(self.logCat, "Could not disable tracking",
			util.Fields{"deviceId": devId,
				"error": err.Error()})
	} else {
		self.logger.Info(self.logCat, "Disabling tracking",
			util.Fields{"deviceId": devId})
		store.StoreCommand(devId, string(jnt), "t")
		// send the push if possible.
		if devRec, err := store.GetDeviceInfo(devId); err == nil {
			self.logger.Debug(self.logCat, "Sending Push",
				util.Fields{"deviceId": devId,
					"cmd": "t:0"})
			SendPush(devRec, self.config)
		}
	}
	return err
}

// log the device's position reply
func (self *Handler) updatePage(devId, cmd string, args map[string]interface{}, logPosition bool) (err error) {
	var location storage.Position
	var hasPasscode bool

	store := self.store

	// Only record a location if there is one.
	// Device reports OK:false on errors
	if b, ok := args["ok"]; ok && b.(bool) == true {
		for key, arg := range args {
			if len(key) < 2 {
				continue
			}
			switch k := strings.ToLower(key[:2]); k {
			case "la":
				location.Latitude = arg.(float64)
			case "lo":
				location.Longitude = arg.(float64)
			case "al":
				location.Altitude = arg.(float64)
			case "ac":
				location.Accuracy = arg.(float64)
			case "ti":
				location.Time = int64(arg.(float64))
				if location.Time == 0 {
					return nil
				}
				// has_lockcode
			case "ha":
				if self.config.GetFlag("ek.ignore_passcode_state") {
					hasPasscode = false
					args[key] = false
				} else {
					hasPasscode = isTrue(arg)
					if err = store.SetDeviceLock(devId, hasPasscode); err != nil {
						return err
					}
				}
			}
		}
		if logPosition {
			if err = store.SetDeviceLocation(devId, location); err != nil {
				return err
			}
			// because go sql locking.
			store.GcDatabase(devId, "")
		}
	}
	location.Cmd = storage.Unstructured{cmd: args}

	// this defer also catches and logs panics from the i.Socket.Write()
	defer func(logger *util.HekaLogger, logCat, devId string) {
		if r := recover(); r != nil {
			err := r.(error)
			logger.Error(logCat,
				"Panic in WS handler",
				util.Fields{"error": err.Error(),
					"deviceId": devId})
		}
	}(self.logger, self.logCat, devId)

	muClient.RLock()
	clients, ok := Clients[devId]
	muClient.RUnlock()

	if ok {
		js, _ := json.Marshal(location)
		fmt.Printf("### Sending update to %d pages: %s\n", len(clients), js)
		for _, i := range clients {
			i.Socket.Write(js)
		}
	} else {
		self.logger.Warn(self.logCat,
			"No clients for device",
			util.Fields{"deviceid": devId})
	}
	return nil
}

// log the cmd reply from the device.
func (self *Handler) logReply(devId, cmd string, args replyType) (err error) {
	// verify state and store it

	if v, ok := args["ok"]; !ok {
		return ErrInvalidReply
	} else {
		if !isTrue(v) {
			if e, ok := args["error"]; ok {
				return errors.New(e.(string))
			}
			return errors.New("Unknown error")
		}
		// log the state? (Device is currently cmd-ing)?
		store := self.store
		err = store.Touch(devId)
	}
	return err
}

// Check that a given string intval is within a range.
func (self *Handler) rangeCheck(s string, min, max int64) int64 {
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		self.logger.Warn(self.logCat, "Unparsable range value, returning 0",
			util.Fields{"error": err.Error(),
				"string": s})
		return 0
	}
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// Verify the HAWK header value from the client
func (self *Handler) verifyHawkHeader(req *http.Request, body []byte, devRec *storage.Device) bool {
	var err error

	if devRec == nil {
		self.logger.Error(self.logCat, "Could not validate Hawk header: devRec is nil", nil)
		return false
	}

	if self.config.GetFlag("hawk.OKBlank") && devRec.Secret == "" {
		self.logger.Info(self.logCat, "Allowing old device",
			util.Fields{"deviceId": devRec.ID})
		return true
	}

	// Remote Hawk
	rhawk := Hawk{logger: self.logger, config: self.config}
	// Local Hawk
	lhawk := Hawk{logger: self.logger, config: self.config}
	// Get the remote signature from the header
	err = rhawk.ParseAuthHeader(req, self.logger)
	if err != nil {
		self.logger.Error(self.logCat, "Could not parse Hawk header",
			util.Fields{"error": err.Error()})
		return false
	}

	// Generate the comparator signature from what we know.
	lhawk.Nonce = rhawk.Nonce
	lhawk.Time = rhawk.Time
	// getting intermittent sig clashes. I'm copying time, but i don't know if the
	// proxy could be causing issues as well. Set the method from the source here.
	lhawk.Method = rhawk.Method
	//lhawk.Hash = rhawk.Hash

	err = lhawk.GenerateSignature(req, rhawk.Extra, string(body),
		devRec.Secret)
	if err != nil {
		self.logger.Error(self.logCat, "Could not verify sig",
			util.Fields{"error": err.Error()})
		return false
	}
	// Do they match?
	if !lhawk.Compare(rhawk.Signature) {
		self.logger.Error(self.logCat, "Cmd:Invalid Hawk Signature",
			util.Fields{
				"expecting": lhawk.Signature,
				"got":       rhawk.Signature,
			})
		if self.config.GetFlag("hawk.disabled") {
			return true
		}
		return false
	}
	return true
}

// A simple signature generator for WS connections
// Unfortunately, remote IP is not reliable for WS.
func (self *Handler) genSig(req *http.Request, session *sessions.Session) (ret string, err error) {
	if session == nil {
		session, _ = sessionStore.Get(req, SESSION_NAME)
	}
	if sess, ok := session.Values[SESSION_DEVICEID]; !ok {
		return "", errors.New("Invalid")
	} else {
		sig := self.genHash(sess.(string) +
			session.Values[SESSION_USERID].(string))
		/*
		   fmt.Printf("@@@ Remote Addr: %s, %s, %s\n",
		       req.RemoteAddr,
		       req.Header.Get("X-Real-IP"),
		       req.Header.Get("X-Forwarded-For"))
		*/
		return sig, nil
	}
}

// Check the simple WS signature against the second to last item
func (self *Handler) checkSig(req *http.Request, devId string) (ok bool) {

	return true

	bits := strings.Split(req.URL.Path, "/")
	// remember, leading "/" counts.
	gotsig := bits[len(bits)-2]
	testsig, err := self.genSig(req, nil)
	if err != nil {
		return false
	}
	return testsig == gotsig
}

// get the OAuth2 Access token
func (self *Handler) getAccessToken(code string) (accessToken string, err error) {
	token_url := self.config.Get("fxa.token", OAUTH_ENDPOINT+"/v1/token")
	vals := make(map[string]string)
	vals["client_id"] = self.config.Get("fxa.client_id", "invalid")
	vals["client_secret"] = self.config.Get("fxa.client_secret", "invalid")
	vals["code"] = code
	vd, err := json.Marshal(vals)
	if err != nil {
		self.logger.Error(self.logCat, "Could not marshal vals to json",
			util.Fields{"error": err.Error()})
		return "", err
	}
	// fmt.Printf("### sending to %s\n %s\n", token_url, vd)
	req, err := http.NewRequest("POST", token_url, bytes.NewBuffer(vd))
	if err != nil {
		self.logger.Error(self.logCat, "Could not get oauth token",
			util.Fields{"code": code, "error": err.Error()})
		return "", ErrOauth
	}
	req.Header.Add("Content-Type", "application/json")
	cli := http.DefaultClient
	res, err := cli.Do(req)
	if err != nil {
		self.logger.Error(self.logCat, "Access Token Fetch failed",
			util.Fields{"error": err.Error()})
		return "", err
	}
	reply, raw, err := parseBody(res.Body)
	if code, ok := reply["code"]; ok && code.(float64) > 299.0 {
		self.logger.Error(self.logCat, "FxA Access token failure",
			util.Fields{"code": strconv.FormatFloat(code.(float64), 'f', 1, 64),
				"body": raw})
		return "", ErrOauth
	}
	token, ok := reply["access_token"]
	if !ok {
		self.logger.Error(self.logCat, "OAuth Access token missing from reply",
			util.Fields{"code": code})
		return "", ErrOauth
	}
	return token.(string), nil
}

// Get the user's Email from the profile server using the OAuth2 access token
func (self *Handler) getUserEmail(accessToken string) (email string, err error) {
	client := http.DefaultClient
	url := self.config.Get("fxa.content.endpoint", CONTENT_ENDPOINT) + "/email"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		self.logger.Error(self.logCat, "Could not POST to get email",
			util.Fields{"error": err.Error()})
		return "", err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	// fmt.Printf("### Sending email request to profile server\n%+v\n", req)
	resp, err := client.Do(req)
	if err != nil {
		self.logger.Error(self.logCat, "Could not get user email",
			util.Fields{"error": err.Error()})
		return "", err
	}
	buffer, raw, err := parseBody(resp.Body)
	if err != nil {
		self.logger.Error(self.logCat, "Could not parse body",
			util.Fields{"error": err.Error()})
		return "", err
	}
	if _, ok := buffer["email"]; !ok {
		self.logger.Error(self.logCat, "Response did not contain email",
			util.Fields{"body": raw})
		return "", ErrNoUser
	}
	// fmt.Printf("### Got email! %s\n", buffer["email"].(string))
	return buffer["email"].(string), nil
}

// Generate a hash from the string.
func (self *Handler) genHash(input string) (output string) {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func socketError(socket *websocket.Conn, msg string) {
	out, _ := json.Marshal(util.Fields{"error": msg})
	socket.Write(out)
}

//Handler Public Functions

func NewHandler(config *util.MzConfig, logger *util.HekaLogger, metrics *util.Metrics) *Handler {
	store, err := storage.Open(config, logger, metrics)
	if err != nil {
		logger.Error("Handler", "Could not open storage",
			util.Fields{"error": err.Error()})
		return nil
	}

	sessionSecret := config.Get("session.secret", "")
	if sessionSecret == "" {
		logger.Error("Handler", "No session secret defined.", nil)
		return nil
	}
	sessionCrypt := config.Get("session.crypt", "")
	if sessionCrypt == "" {
		sessionCrypt = string(securecookie.GenerateRandomKey(16))
	} else {
		b, err := base64.StdEncoding.DecodeString(sessionSecret)
		if err != nil {
			sessionCrypt = string(securecookie.GenerateRandomKey(16))
		} else {
			sessionCrypt = string(b)
		}
	}
	sessionStore = sessions.NewCookieStore([]byte(sessionSecret),
		[]byte(sessionCrypt))
	sessionStore.Options = &sessions.Options{
		Domain: config.Get("session.domain", "localhost"),
		Path:   "/",
		// Do not set a max age by default.
		// This confuses gorilla, which winds up setting two "user" cookies.
		//MaxAge: 3600 * 24,
	}
	maxCli, _ := strconv.ParseInt(config.Get("ws.max_clients", "0"), 10, 64)

	// Initialize the data store once. This creates tables and
	// applies required changes.
	store.Init()

	return &Handler{config: config,
		logger:  logger,
		logCat:  "handler",
		metrics: metrics,
		store:   store,
		maxCli:  maxCli,
	}
}

// Register a new device
func (self *Handler) Register(resp http.ResponseWriter, req *http.Request) {

	var buffer = util.JsMap{}
	var userid string
	var email string
	var user string
	var pushUrl string
	var deviceid string
	var devRec *storage.Device
	var secret string
	var accepts string
	var hasPasscode bool
	var loggedIn bool
	var err error
	var raw string

	self.logCat = "handler:Register"
	resp.Header().Set("Content-Type", "application/json")
	// Do not set a session here. Use HAWK and URL to validate future
	// calls from the device.

	store := self.store

	buffer, raw, err = parseBody(req.Body)
	if err != nil {
		http.Error(resp, "No body", http.StatusBadRequest)
	} else {
		loggedIn = false
		if val, ok := buffer["deviceid"]; !ok || len(val.(string)) == 0 {
			deviceid, _ = util.GenUUID4()
		} else {
			// User provided a deviceid in the PATH, screen and see if we
			// have any info about it.
			deviceid = strings.Map(deviceIdFilter, val.(string))
			if len(deviceid) > 32 {
				deviceid = deviceid[:32]
			}
			devRec, err = store.GetDeviceInfo(deviceid)
			if err != nil {
				self.logger.Warn(self.logCat, "Could not get info for deviceid",
					util.Fields{"deviceid": deviceid,
						"error": err.Error()})
			}
		}
		// If there's an assertion, validate it and pull user info.
		if assertion, ok := buffer["assert"]; ok {
			if self.config.GetFlag("auth.persona") {
				userid, email, err = self.verifyPersonaAssertion(assertion.(string))
			} else {
				userid, email, err = self.verifyFxAAssertion(assertion.(string))
			}
			if err != nil || userid == "" {
				http.Error(resp, "Unauthorized", 401)
				return
			}
			self.logger.Debug(self.logCat, "Got user "+email, nil)
			loggedIn = true
		} else {
			// Huh, no assertion. Check the HAWK header to see if the
			// user is valid or not. If so, get the user registered for
			// this device.
			self.logger.Warn(self.logCat, "Missing 'assert' value",
				util.Fields{"body": raw})
			// Use HAWK + deviceid to determine if this is a re-registration.
			if hv := self.verifyHawkHeader(req,
				[]byte(raw),
				devRec); devRec != nil && hv {
				self.logger.Info(self.logCat,
					"Hawk Verified, getting user info ...\n",
					nil)
				if userid, user, err = store.GetUserFromDevice(deviceid); err == nil {
					self.logger.Debug(self.logCat,
						"Got user info ",
						util.Fields{"userId": userid,
							"name":     user,
							"deviceId": deviceid})
					loggedIn = true
				} else {
					self.logger.Error(self.logCat,
						"No user associated with valid device!!",
						util.Fields{"deviceId": deviceid})
				}
			} else {
				self.logger.Warn(self.logCat,
					"Failed Hawk Header Check",
					util.Fields{"deviceId": deviceid})
			}
		}
		if !loggedIn {
			self.logger.Error(self.logCat, "Device Not logged in",
				util.Fields{"deviceId": deviceid})
			http.Error(resp, "Unauthorized", 401)
			return
		}
		// If there's a pushUrl specified, make sure it's not empty.
		if val, ok := buffer["pushurl"]; !ok || val == nil || len(val.(string)) == 0 {
			self.logger.Error(self.logCat, "Missing SimplePush url", nil)
			http.Error(resp, "Bad Data", 400)
			return
		} else {
			pushUrl = val.(string)
		}
		//ALWAYS generate a new secret on registration!
		secret = GenNonce(16)
		if val, ok := buffer["has_passcode"]; !ok {
			hasPasscode = true
		} else {
			hasPasscode, err = strconv.ParseBool(val.(string))
			if err != nil {
				hasPasscode = false
			}
		}
		if self.config.GetFlag("ek.ignore_passcode_state") {
			// This overrides the passcode state reported by the device.
			// This is a work around for a device lock screen bug that
			// caches the last pass code, even if the user has disabled
			// the device pass code.
			hasPasscode = false
		}
		if val, ok := buffer["accepts"]; ok {
			// collapse the array to a string
			if l := len(val.([]interface{})); l > 0 {
				acc := make([]byte, l)
				for n, ke := range val.([]interface{}) {
					acc[n] = ke.(string)[0]
				}
				accepts = strings.ToLower(string(acc))
			}
		}
		if len(accepts) == 0 {
			accepts = "elrth"
		}
		if !strings.Contains("h", accepts) {
			accepts = accepts + "h"
		}

		// create the new device record
		var devId string
		if user == "" {
			user = strings.SplitN(email, "@", 2)[0]
		}
		if devId, err = store.RegisterDevice(
			userid,
			storage.Device{
				ID:          deviceid,
				Name:        user,
				Secret:      secret,
				PushUrl:     pushUrl,
				HasPasscode: hasPasscode,
				Accepts:     accepts,
			}); err != nil {
			self.logger.Error(self.logCat, "Error Registering device", nil)
			http.Error(resp, "Bad Request", 400)
			return
		} else {
			if devId != deviceid {
				self.logger.Error(self.logCat, "Different deviceID returned",
					util.Fields{"original": deviceid, "new": devId})
				http.Error(resp, "Server error", 500)
				return
			}
			self.devId = deviceid
		}
	}
	self.metrics.Increment("device.registration")
	self.updatePage(self.devId, "register", buffer, false)
	output, err := json.Marshal(util.Fields{"deviceid": self.devId,
		"secret": secret,
		//"email":    email,
		"clientid": userid,
	})
	if err != nil {
		self.logger.Error(self.logCat, "Could not marshal reply",
			util.Fields{"error": err.Error()})
		return
	}
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
	return
}

// Handle the Cmd response from the device and pass next command if available.
func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
	var err error
	var l int

	self.logCat = "handler:Cmd"
	resp.Header().Set("Content-Type", "application/json")
	store := self.store

	// fmt.Printf("### req.URL: %s", req.URL)
	deviceId := getDevFromUrl(req.URL)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}

	devRec, err := store.GetDeviceInfo(deviceId)
	if err != nil {
		switch err {
		case storage.ErrUnknownDevice:
			self.logger.Error(self.logCat,
				"Unknown device requesting cmd",
				util.Fields{
					"deviceId": deviceId})
			http.Error(resp, "Unauthorized", 401)
		default:
			self.logger.Error(self.logCat,
				"Cmd:Unhandled Error",
				util.Fields{
					"error":    err.Error(),
					"deviceId": deviceId})
			http.Error(resp, "Unauthorized", 401)
		}
		return
	}
	//decode the body
	var body = make([]byte, req.ContentLength)
	l, err = req.Body.Read(body)
	if err != nil && err != io.EOF {
		self.logger.Error(self.logCat, "Could not read body",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Invalid", 400)
		return
	}
	//validate the Hawk header
	if self.config.GetFlag("hawk.disabled") == false {
		if !self.verifyHawkHeader(req, body, devRec) {
			http.Error(resp, "Unauthorized", 401)
			return
		}
	}
	// Do the command.
	self.logger.Info(self.logCat, "### Handling cmd response from device",
		util.Fields{
			"deviceid": deviceId,
			"cmd":      string(body),
			"length":   fmt.Sprintf("%d", l),
		})
	// Ignore effectively null commands (e.g. "" or {})
	if l > 2 {
		reply := make(replyType)
		merr := json.Unmarshal(body, &reply)
		//	merr := json.Unmarshal(body, &reply)
		if merr != nil {
			self.logger.Error(self.logCat,
				"Could not unmarshal data",
				util.Fields{
					"error": merr.Error(),
					"body":  string(body)})
			http.Error(resp, "Server Error", 500)
			return
		}

		for cmd, args := range reply {
			var margs replyType
			if cmd == "" {
				continue
			}
			c := strings.ToLower(string(cmd))
			cs := string(c[0])
			/*
				            // TODO : fix command filter
							if !strings.Contains(devRec.Accepts, cs) {
								self.logger.Warn(self.logCat, "Unacceptable Command",
									util.Fields{"unacceptable": cs,
										"acceptable": devRec.Accepts})
								continue
							}
			*/
			self.metrics.Increment("cmd.received." + cs)
			// Normalize the args.
			switch args.(type) {
			case bool:
				margs = replyType{string(cmd): isTrue(args.(bool))}
			default:
				margs = args.(map[string]interface{})
			}
			// handle the client response
			err = store.Touch(deviceId)
			switch cs {
			case "t":
				err = self.updatePage(deviceId, c, margs, true)
			case "q":
				// User has quit, nuke what we know.
				if self.config.GetFlag("cmd.q.allow") {
					err = store.DeleteDevice(deviceId)
				}
			default:
				err = self.updatePage(deviceId, c, margs, false)
			}
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error handling command",
					util.Fields{"error": err.Error(),
						"cmd":      string(cmd),
						"deviceId": deviceId,
						"args":     fmt.Sprintf("%v", args)})
				http.Error(resp,
					"\"Server Error\"",
					http.StatusServiceUnavailable)
				return
			}
		}
	}

	// reply with pending commands
	//
	cmd, err := store.GetPending(deviceId)
	var output = []byte(cmd)
	if err != nil {
		self.logger.Error(self.logCat, "Could not send commands",
			util.Fields{"error": err.Error()})
		http.Error(resp, "\"Server Error\"", http.StatusServiceUnavailable)
	}
	if output == nil || len(output) < 2 {
		output = []byte("{}")
	}
	hawk := Hawk{config: self.config, logger: self.logger}
	authHeader := hawk.AsHeader(req, devRec.ID, string(output),
		"", devRec.Secret)
	resp.Header().Add("Authorization", authHeader)
	// total cheat to get the command without parsing the cmd data.
	if len(cmd) > 2 {
		self.metrics.Increment("cmd.send." + string(cmd[2]))
	}
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
}

// Queue the command from the Web Front End for the device.
func (self *Handler) Queue(devRec *storage.Device, cmd string, args, rep *replyType) (status int, err error) {
	status = http.StatusOK

	self.logCat = "handler:Queue"
	deviceId := devRec.ID
	// sanitize values.
	var v interface{}
	var ok bool
	lcmd := strings.ToLower(cmd)
	c := string(cmd[0])
	self.logger.Debug(self.logCat, "Processing UI Command",
		util.Fields{"cmd": cmd})
	if !strings.Contains(devRec.Accepts, c) {
		// skip unacceptable command
		self.logger.Warn(self.logCat, "Agent does not accept command",
			util.Fields{"unacceptable": c,
				"acceptable": devRec.Accepts})
		(*rep)["error"] = 422
		(*rep)["cmd"] = cmd
		return
	}
	rargs := *args
	var vs string
	switch c {
	case "l":
		if v, ok = rargs["c"]; ok {
			max, err := strconv.ParseInt(self.config.Get("cmd.c.max", "9999"),
				10, 64)
			if err != nil {
				max = 9999
			}
			switch v.(type) {
			case string:
				vs = v.(string)
			case int64:
			case float64:
				vs = strconv.FormatInt(int64(v.(int64)), 10)
			}
			// make sure that the lock code is a valid four digit string.
			// otherwise we may lock users out of their phones.
			rargs["c"] = fmt.Sprintf("%04d", self.rangeCheck(
				strings.Map(digitsOnly, vs[:minInt(4, len(vs))]),
				0, max))
		}
		if v, ok = rargs["m"]; ok {
			vs = v.(string)
			if self.config.GetFlag("ascii_message_only") {
				vs = strings.Map(asciiOnly,
					string(vs))
			}
			vr := []rune(vs)
			vb := []byte(vs)
			trimmed := vr[:minInt(100,
				utf8.RuneCount(vb))]
			rargs["m"] = string(trimmed)
		}
	case "r", "t":
		if v, ok = rargs["d"]; ok {
			max, err := strconv.ParseInt(
				self.config.Get("cmd."+c+".max",
					"10500"), 10, 64)
			if err != nil {
				max = 10500
			}
			switch v.(type) {
			case string:
				vs = v.(string)
			case float64:
				vs = strconv.FormatFloat(v.(float64), 'f', 0, 64)
			default:
				vs = fmt.Sprintf("%s", v)
			}
			rargs["d"] = self.rangeCheck(
				strings.Map(digitsOnly, vs),
				0,
				max)
		}
	case "e":
		rargs = replyType{}
	default:
		self.logger.Warn(self.logCat, "Invalid Command",
			util.Fields{"cmd": string(cmd),
				"deviceId": deviceId,
				"args":     fmt.Sprintf("%v", rargs)})
		return http.StatusBadRequest, errors.New("\"Invalid Command\"")
	}
	fixed, err := json.Marshal(storage.Unstructured{c: rargs})
	if err != nil {
		// Log the error
		self.logger.Error(self.logCat, "Error handling command",
			util.Fields{"error": err.Error(),
				"cmd":      string(cmd),
				"deviceId": deviceId,
				"args":     fmt.Sprintf("%v", rargs)})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}

	store := self.store

	err = store.StoreCommand(deviceId, string(fixed), lcmd)
	if err != nil {
		// Log the error
		self.logger.Error(self.logCat, "Error storing command",
			util.Fields{"error": err.Error(),
				"cmd":      string(cmd),
				"deviceId": deviceId,
				"args":     fmt.Sprintf("%v", args)})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}
	// trigger the push
	self.metrics.Increment("cmd.store." + c)
	self.metrics.Increment("push.send")
	self.logger.Debug(self.logCat,
		"Sending Push",
		util.Fields{"deviceId": deviceId,
			"cmd": c})
	err = SendPush(devRec, self.config)
	if err != nil {
		self.logger.Error(self.logCat, "Could not send Push",
			util.Fields{"error": err.Error(),
				"pushUrl": devRec.PushUrl})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}
	return
}

// Accept a command to queue from the REST interface
func (self *Handler) RestQueue(resp http.ResponseWriter, req *http.Request) {
	/* Queue commands for the device.
	 */
	var err error
	var lbody int

	resp.Header().Set("Content-Type", "application/json")
	rep := make(replyType)
	self.logCat = "handler:Queue"

	session, err := sessionStore.Get(req, SESSION_NAME)
	if err != nil {
		self.logger.Error(self.logCat, "Unauthorized access to Cmd",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Unauthorized", 401)
		return
	}
	store := self.store

	deviceId := getDevFromUrl(req.URL)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	userId, _, err := self.getUser(resp, req)
	if userId == "" || err != nil {
		self.logger.Error(self.logCat, "No userid", nil)
		self.clearSession(session)
		session.Options.MaxAge = -1
		session.Save(req, resp)
		http.Error(resp, "Unauthorized", 401)
		return
	}

	devRec, err := store.GetDeviceInfo(deviceId)
	// fmt.Printf("### devices: %+v\n", devRec)
	if err != nil || devRec == nil {
		fields := util.Fields{"deviceId": deviceId}
		if err != nil {
			fields["error"] = err.Error()
		}
		if devRec != nil {
			fields["devRec"] = devRec.ID
		}
		self.logger.Error(self.logCat, "Could not get userid", fields)
		self.clearSession(session)
		session.Options.MaxAge = -1
		session.Save(req, resp)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if devRec.User != userId {
		self.logger.Error(self.logCat, "Unauthorized device",
			util.Fields{"devrec": devRec.User,
				"userId": userId})
		self.clearSession(session)
		session.Options.MaxAge = -1
		session.Save(req, resp)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if devRec == nil {
		self.logger.Error(self.logCat,
			"Queue:User requested unknown device",
			util.Fields{
				"deviceId": deviceId,
				"userId":   userId})
		self.clearSession(session)
		session.Options.MaxAge = -1
		session.Save(req, resp)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if err != nil {
		switch err {
		default:
			self.logger.Error(self.logCat,
				"Cmd:Unhandled Error",
				util.Fields{
					"error":    err.Error(),
					"deviceId": deviceId})
			http.Error(resp, "Unauthorized", 401)
		}
		return
	}

	//decode the body
	var body = make([]byte, req.ContentLength)
	lbody, err = req.Body.Read(body)
	if err != nil && err != io.EOF {
		self.logger.Error(self.logCat, "Could not read body",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Invalid", 400)
		return
	}
	self.logger.Info(self.logCat, "Handling cmd from UI",
		util.Fields{
			"cmd":    string(body),
			"length": fmt.Sprintf("%d", lbody),
		})
	if lbody > 0 {
		reply := make(replyType)
		merr := json.Unmarshal(body, &reply)
		//	merr := json.Unmarshal(body, &reply)
		if merr != nil {
			self.logger.Error(self.logCat, "Could not unmarshal data",
				util.Fields{
					"error": merr.Error(),
					"body":  string(body)})
			http.Error(resp, "Server Error", 500)
			return
		}

		for cmd, args := range reply {
			rargs := replyType(args.(map[string]interface{}))
			status, err := self.Queue(devRec, cmd, &rargs, &rep)
			if err != nil {
				self.logger.Error(self.logCat, "Error processing command",
					util.Fields{
						"error": err.Error(),
						"cmd":   cmd,
						"args":  fmt.Sprintf("%+v", args)})
				http.Error(resp, err.Error(), status)
				return
			}
		}
	}
	output, _ := json.Marshal(rep)
	self.metrics.Increment("cmd.queued.rest")
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
}

func (self *Handler) UserDevices(resp http.ResponseWriter, req *http.Request) {
	self.logCat = "handler:userDevices"
	type devList struct {
		ID   string
		Name string
		URL  string
	}

	var data struct {
		UserId     string
		DeviceList []devList
	}

	session, err := sessionStore.Get(req, SESSION_NAME)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not initialize session",
			util.Fields{"error": err.Error()})
		//TODO: return error, clear cookie?
		return
	}
	store := self.store

	sessionInfo, err := self.getSessionInfo(resp, req, session)
	if err == nil && len(sessionInfo.UserId) > 0 {
		data.UserId = sessionInfo.UserId
	} else {
		self.logger.Error(self.logCat,
			"Could not get user id",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Needs Auth", 401)
		return
	}

	deviceList, err := store.GetDevicesForUser(data.UserId)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not get devices for user",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", 500)
		return
	}

	var reply []devList
	verRoot := strings.SplitN(self.config.Get("VERSION", "0"), ".", 2)[0]
	if _, ok := session.Values[SESSION_USERID]; !ok {
		session.Values[SESSION_USERID] = data.UserId
	}
	for _, d := range deviceList {
		session.Values[SESSION_DEVICEID] = d.ID
		sig, err := self.genSig(req, session)
		if err != nil {
			continue
		}
		reply = append(reply, devList{
			ID:   d.ID,
			Name: d.Name,
			URL: fmt.Sprintf("%s://%s/%s/ws/%s/%s",
				self.config.Get("ws.proto",
					self.config.Get("ws_proto", "wss")),
				self.config.Get("ws.hostname",
					self.config.Get("ws_hostname", "localhost")),
				verRoot,
				sig,
				d.ID)})
	}
	output, err := json.Marshal(map[string][]devList{
		"devices": reply})
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not marshal output",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", 500)
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
	return
}

// user login functions

func (self *Handler) Index(resp http.ResponseWriter, req *http.Request) {
	self.logCat = "handler:Index"

	docRoot := self.config.Get("document_root", "./static/app")
	if strings.Index(req.URL.Path, "/static") == 0 {
		self.Static(resp, req)
		return
	}
	var err error
	var session *sessions.Session

	session, err = sessionStore.Get(req, SESSION_NAME)
	if err != nil {
		self.logger.Warn(self.logCat,
			"Could not initialize session",
			util.Fields{"error": err.Error()})
	}
	// fmt.Printf("### Index:: session %+v\n", session)
	sessionInfo, err := self.getSessionInfo(resp, req, session)
	initData, err := self.initData(resp, req, sessionInfo)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not get inital data for index",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 401)
		return
	}

	tmpl, err := template.New("index.html").ParseFiles(docRoot + "/index.html")
	if err != nil {
		self.logger.Error(self.logCat, "Could not display index page",
			util.Fields{"error": err.Error(),
				"user": initData.UserId})
		http.Error(resp, "Server error", 500)
	}
	if sessionInfo != nil {
		session.Values[SESSION_USERID] = sessionInfo.UserId
		session.Values[SESSION_EMAIL] = sessionInfo.Email
		session.Values[SESSION_DEVICEID] = sessionInfo.DeviceId
		if err = session.Save(req, resp); err != nil {
			self.logger.Error(self.logCat,
				"Could not save session",
				util.Fields{"error": err.Error()})
		}
	}
	if err = tmpl.Execute(resp, initData); err != nil {
		self.logger.Error(self.logCat,
			"Could not execute template",
			util.Fields{"error": err.Error()})
	}
	self.metrics.Increment("page.index")
	return
}

// Return the initData as a JSON object
func (self *Handler) InitDataJson(resp http.ResponseWriter, req *http.Request) {
	self.logCat = "handler:InitData"

	var err error

	session, err := sessionStore.Get(req, SESSION_NAME)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not initialize session",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", 500)
		return
	}

	sessionInfo, err := self.getSessionInfo(resp, req, session)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not get sessionInfo",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Not Authorized", 401)
		return
	}

	initData, err := self.initData(resp, req, sessionInfo)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not get initial data for index",
			util.Fields{"error": err.Error(),
				"sessionInfo": fmt.Sprintf("%+v", sessionInfo)})
		http.Error(resp, "Server Error", 500)
		return
	}
	resp.Header().Set("Content-Type", "application/json")
	output, err := json.Marshal(initData)
	if err == nil {
		if self.config.GetFlag("debug.show_output") {
			self.logger.Debug(self.logCat,
				">>>output",
				util.Fields{"output": string(output)})
		}
		resp.Write([]byte(output))
		return
	}
	self.logger.Error(self.logCat,
		"Could not marshal data to json",
		util.Fields{"error": err.Error()})
	http.Error(resp, "Server Error", 500)
	return
}

// Show the state of the user's devices.
func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
	// get session info
	self.logCat = "handler:State"

	resp.Header().Set("Content-Type", "application/json")

	store := self.store

	session, err := sessionStore.Get(req, SESSION_NAME)
	if err != nil {
		self.logger.Error(self.logCat, "Could not get session info",
			util.Fields{"error": err.Error()})
		http.Error(resp, err.Error(), 500)
	}
	sessionInfo, err := self.getSessionInfo(resp, req, session)
	if err != nil && err != ErrNoUser {
		session.Options.MaxAge = -1
		session.Save(req, resp)
		http.Error(resp, err.Error(), 401)
		return
	}
	devInfo, err := store.GetDeviceInfo(sessionInfo.DeviceId)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}
	// add the user session cookie
	if sessionInfo != nil {
		session.Values[SESSION_USERID] = sessionInfo.UserId
		session.Values[SESSION_DEVICEID] = sessionInfo.DeviceId
		session.Values[SESSION_EMAIL] = sessionInfo.Email
		session.Values[SESSION_TOKEN] = sessionInfo.AccessToken
	}
	session.Save(req, resp)
	if self.config.GetFlag("ek.ignore_passcode_state") {
		devInfo.HasPasscode = false
	}
	// display the device info...
	output, err := json.Marshal(devInfo)
	if err == nil {
		if self.config.GetFlag("debug.show_output") {
			self.logger.Debug(self.logCat,
				">>>output",
				util.Fields{"output": string(output)})
		}
		resp.Write([]byte(output))
	}
}

// Show the status of the program (For Load Balancers)
func (self *Handler) Status(resp http.ResponseWriter, req *http.Request) {
	self.logCat = "handler:Status"

	resp.Header().Set("Content-Type", "application/json")
	reply := replyType{
		"status":     "ok",
		"goroutines": runtime.NumGoroutine(),
		"version":    self.config.Get("VERSION", "unknown"),
	}
	output, _ := json.Marshal(reply)
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
}

// Handle requests for static content (should be an NGINX rule)
func (self *Handler) Static(resp http.ResponseWriter, req *http.Request) {
	/* This should be handled by something like an nginx rule
	 */

	if !self.config.GetFlag("use_insecure_static") {
		return
	}

	docRoot := self.config.Get("document_root", "static/app/")

	http.ServeFile(resp, req, docRoot+req.URL.Path)
}

// Display the current metrics as a JSON snapshot
func (self *Handler) Metrics(resp http.ResponseWriter, req *http.Request) {
	snapshot := self.metrics.Snapshot()

	resp.Header().Set("Content-Type", "application/json")
	output, err := json.Marshal(snapshot)
	if err != nil {
		self.logger.Error(self.logCat, "Could not generate metrics report",
			util.Fields{"error": err.Error()})
		if self.config.GetFlag("debug.show_output") {
			self.logger.Debug(self.logCat,
				">>>output",
				util.Fields{"output": "{}"})
		}
		resp.Write([]byte("{}"))
		return
	}
	if output == nil {
		output = []byte("{}")
	}
	if self.config.GetFlag("debug.show_output") {
		self.logger.Debug(self.logCat,
			">>>output",
			util.Fields{"output": string(output)})
	}
	resp.Write(output)
}

func (self *Handler) OAuthCallback(resp http.ResponseWriter, req *http.Request) {
	var nonce string
	self.logCat = "oauth"

	// Get the session so that we can save it.
	session, _ := sessionStore.Get(req, SESSION_NAME)
	loginSession, _ := sessionStore.Get(req, SESSION_LOGIN)

	if ni, ok := loginSession.Values["nonce"]; !ok {
		// No nonce, no service
		self.logger.Error(self.logCat, "Missing nonce", nil)
		http.Redirect(resp, req, "/", http.StatusFound)
		return
	} else {
		nonce = ni.(string)
	}

	store := self.store

	if ok, err := store.CheckNonce(nonce); !ok || err != nil {
		self.logger.Error(self.logCat, "Invalid Nonce", nil)
		http.Redirect(resp, req, "/", http.StatusFound)
		return
	}
	// Nuke the login session cookie
	loginSession.Options.MaxAge = -1
	loginSession.Save(req, resp)

	// fmt.Printf("### oauth session: %+v, err: %s\n", session, err)
	if _, ok := session.Values[SESSION_TOKEN]; !ok {
		// get the "state", and "code"
		state := req.FormValue("state")
		code := req.FormValue("code")
		// TODO: check "state" matches magic code thingy
		if state == "" {
			self.logger.Error(self.logCat, "No State", nil)
			http.Redirect(resp, req, "/", http.StatusFound)
			return
		}
		if state != strings.SplitN(nonce, ".", 2)[0] {
			self.logger.Error(self.logCat, "Invalid nonce", nil)
			http.Redirect(resp, req, "/", http.StatusFound)
			return
		}
		if code == "" {
			self.logger.Error(self.logCat, "Missing code value", nil)
			http.Redirect(resp, req, "/", http.StatusFound)
			return
		}

		// fetch the token:
		// fmt.Printf("### Getting access token\n")
		token, err := self.getAccessToken(code)
		if err != nil {
			self.logger.Error(self.logCat, "Could not get access token",
				util.Fields{"error": err.Error()})
			http.Redirect(resp, req, "/", http.StatusFound)
			return
		}
		// fmt.Printf("### store user token %s\n", token)
		delete(session.Values, SESSION_EMAIL)
		session.Values[SESSION_TOKEN] = token
	}
	if _, ok := session.Values[SESSION_EMAIL]; !ok {
		// fmt.Printf("### Getting user email from access token\n")
		email, err := self.getUserEmail(session.Values[SESSION_TOKEN].(string))
		if err != nil {
			self.logger.Error(self.logCat, "Could not get email",
				util.Fields{"error": err.Error()})
			http.Redirect(resp, req, "/", http.StatusFound)
			return
		}
		session.Values[SESSION_EMAIL] = email
		// fmt.Printf("### Saving session %+v\n", session)
		// awesome. So saving the session apparently doesn't mean it's
		// readable by subsequent session get calls.
		session.Save(req, resp)
	}
	self.metrics.Increment("page.signin.success")
	http.Redirect(resp, req, "/", http.StatusFound)
	return
}

// Handle Websocket processing.
func (self *Handler) WSSocketHandler(ws *websocket.Conn) {
	self.logCat = "handler:Socket"
	store := self.store

	// generate small token ID for this instance. UUID4 probably overkill.
	// covert to int?
	ib := make([]byte, 4)
	rand.Read(ib)
	instance := hex.EncodeToString(ib)
	self.devId = getDevFromUrl(ws.Request().URL)
	if !self.checkSig(ws.Request(), self.devId) {
		self.logger.Error(self.logCat, "Unauthorized access.",
			nil)
		return
	}
	devRec, err := store.GetDeviceInfo(self.devId)
	if err != nil {
		self.logger.Error(self.logCat, "Invalid Device for socket",
			util.Fields{"error": err.Error(),
				"devId": self.devId})
		socketError(ws, "Invalid Device")
		return
	}

	sock := &WWS{
		Socket:  ws,
		Handler: self,
		Device:  devRec,
		Logger:  self.logger,
		Born:    time.Now(),
		Quit:    false}

	defer func(logger *util.HekaLogger) {
		if r := recover(); r != nil {
			debug.PrintStack()
			if logger != nil {
				logger.Error(self.logCat, "Uknown Error",
					util.Fields{"error": r.(error).Error()})
			} else {
				socketError(ws, "Unknown Error")
				log.Printf("Socket Unknown Error: %s\n", r.(error).Error())
			}
		}
	}(sock.Logger)

	if self.devId == "" {
		self.logger.Error(self.logCat, "No deviceID found",
			util.Fields{"error": err.Error(),
				"path": ws.Request().URL.Path})
		socketError(ws, "Invalid Device")
		return
	}

	self.metrics.Increment("page.socket")
	if err := addClient(self.devId, instance, sock, self.maxCli); err != nil {
		self.logger.Error(self.logCat,
			"Could not add WebUI client",
			util.Fields{"deviceId": self.devId,
				"instance": instance,
				"error":    err.Error()})
		socketError(ws, "Too Many Connections")
		return
	}
	defer func(self *Handler, sock *WWS, instance string) {
		self.metrics.Decrement("page.socket")
		self.metrics.Timer("page.socket", int64(time.Since(sock.Born).Seconds()))
		if stopTrack, err := rmClient(self.devId, instance); err != nil {
			self.logger.Error(self.logCat,
				"Could not clean up closed instance!",
				util.Fields{"error": err.Error(),
					"deviceId": self.devId})
		} else {
			if stopTrack {
				self.stopTracking(self.devId, store)
			}
		}
	}(self, sock, instance)
	sock.Run()
}

func (self *Handler) Signin(resp http.ResponseWriter, req *http.Request) {
	var err error
	store := self.store

	session, _ := sessionStore.Get(req, SESSION_LOGIN)
	if session.Values["nonce"], err = store.GetNonce(); err != nil {
		self.logger.Error(self.logCat,
			"Could not assign nonce",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	prefix := "fxa"
	if self.config.GetFlag("auth.persona") {
		prefix = "persona"
	}
	redirUrlTemplate := self.config.Get(prefix+".login_url",
		"{{.Host}}?client_id={{.ClientId}}&scope=profile:email&state={{.State}}&action=signin")
	tmpl, err := template.New("Login").Parse(redirUrlTemplate)
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not handle login template",
			util.Fields{"error": err.Error(),
				"template": redirUrlTemplate})
		http.Error(resp, "Server error", 500)
		return
	}
	// fill the template using an anonymous struct.
	// (if this works, I'm a bit grossed out by go)
	var buffer = new(bytes.Buffer)

	err = tmpl.Execute(buffer, struct {
		Host     string
		ClientId string
		State    string
	}{
		self.config.Get(prefix+".login", "http://localhost/"),
		self.config.Get(prefix+".client_id", ""),
		strings.SplitN(session.Values["nonce"].(string), ".", 2)[0],
	})
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not fill out template",
			util.Fields{"error": err.Error(),
				"template": redirUrlTemplate})
		http.Error(resp, "Server error", 500)
		return
	}

	session.Options.HttpOnly = true
	session.Options.Secure = !config.GetFlag("auth.use_insecure_cookie")

	session.Save(req, resp)
	http.Redirect(resp, req, buffer.String(), http.StatusFound)
	self.metrics.Increment("page.signin.attempt")
	return
}

func (self *Handler) Signout(resp http.ResponseWriter, req *http.Request) {
	for _, name := range []string{SESSION_LOGIN, SESSION_NAME} {
		session, _ := sessionStore.Get(req, name)
		session.Options.MaxAge = -1
		session.Save(req, resp)
	}
	self.metrics.Increment("page.signout.success")
	http.Redirect(resp, req, "/", http.StatusFound)
}

// Validate a given assertion (useful for client)
func (self *Handler) Validate(resp http.ResponseWriter, req *http.Request) {
	var reply = util.JsMap{"valid": false}

	self.logCat = "handler:Validate"
	resp.Header().Set("Content-Type", "application/json")

	// Looking for the body of the request to contain a JSON object with
	// {assert: ... }
	if buffer, raw, err := parseBody(req.Body); err == nil {
		if assert, ok := buffer["assert"]; ok {
			if userid, _, err := self.verifyFxAAssertion(assert.(string)); err == nil {
				reply["valid"] = true
				reply["uid"] = userid
			} else {
				self.logger.Error(self.logCat,
					"Could not verify assertion",
					util.Fields{"error": err.Error()})
			}
		} else {
			self.logger.Error(self.logCat,
				"No assert found in body of POST", nil)
		}
	} else {
		self.logger.Error(self.logCat, "Could not parse body",
			util.Fields{"body": raw, "error": err.Error()})
	}

	// OK, write out the reply object (if you can)
	// as {valid: (true|false), [uid: ... ]}
	if output, err := json.Marshal(reply); err == nil {
		if self.config.GetFlag("debug.show_output") {
			self.logger.Debug(self.logCat,
				">>>output",
				util.Fields{"output": string(output)})
		}
		resp.Write(output)
	} else {
		self.logger.Error(self.logCat, "Could not write reply",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", 500)
	}
}
