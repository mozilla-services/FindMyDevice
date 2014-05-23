package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"code.google.com/p/go.net/websocket"
	"mozilla.org/util"
	"mozilla.org/wmf/storage"

	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
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
}

// Map of clientIDs to socket handlers
type ClientMap map[string]*WWS

var muClient sync.Mutex
var Clients = make(ClientMap)

// Generic reply structure (useful for JSON responses)
type replyType map[string]interface{}

// Each session contains a UserID and a DeviceID
type sessionInfo struct {
	UserId   string
	DeviceId string
}

var ErrInvalidReply = errors.New("Invalid Command Response")
var ErrAuthorization = errors.New("Needs Authorization")

//Handler private functions

// verify a Persona assertion using the config values
// part of Handler for config & logging reasons
func (self *Handler) verifyAssertion(assertion string) (userid, email string, err error) {
	var ok bool
	if self.config.GetFlag("auth.disabled") {
		self.logger.Warn(self.logCat, "!!! Skipping validation...", nil)
//		if len(assertion) == 0 {
			return "user1", "user@example.com", nil
//		}
		// Time to UberFake! THIS IS VERY DANGEROUS!
		self.logger.Warn(self.logCat,
			"!!! Using Assertion Without Validation",
			nil)
		bits := strings.Split(assertion, ".")
		if len(bits) < 2 {
			self.logger.Error(self.logCat, "Invalid assertion",
				util.Fields{"assertion": assertion})
			return "", "", errors.New("Invalid assertion")
		}
		// get the interesting bit
		intBit := bits[1]
		// pad to byte boundry
		intBit = intBit + "===="[:len(intBit)%4]
		decoded, err := base64.StdEncoding.DecodeString(intBit)
		if err != nil {
			self.logger.Error(self.logCat, "Could not decode assertion",
				util.Fields{"error": err.Error()})
			return "", "", err
		}
		asrt := make(replyType)
		err = json.Unmarshal(decoded, &asrt)
		if err != nil {
			self.logger.Error(self.logCat, "Could not unmarshal",
				util.Fields{"error": err.Error()})
			return "", "", err
		}
		email = asrt["principal"].(map[string]interface{})["email"].(string)
		hasher := sha256.New()
		hasher.Write([]byte(email))
		userid = hex.EncodeToString(hasher.Sum(nil))
		self.logger.Debug(self.logCat, "Extracted credentials",
			util.Fields{"userId": userid, "email": email})
		return userid, email, nil
	}

	// Better verify for realz
	validatorURL := self.config.Get("persona.validater_url",
		"https://verifier.login.persona.org/verify")
	audience := self.config.Get("persona.audience",
		"http://localhost:8080")
	body, err := json.Marshal(
		util.Fields{"assertion": assertion,
			"audience": audience})
	if err != nil {
		self.logger.Error(self.logCat,
			"Could not marshal assertion",
			util.Fields{"error": err.Error()})
		return "", "", ErrAuthorization
	}
	req, err := http.NewRequest("POST", validatorURL, bytes.NewReader(body))
	if err != nil {
		self.logger.Error(self.logCat, "Could not POST assertion",
			util.Fields{"error": err.Error()})
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
	buffer, err := parseBody(res.Body)
	if isOk, ok := buffer["status"]; !ok || isOk != "okay" {
		var errStr string
		if err != nil {
			errStr = err.Error()
		} else if _, ok = buffer["reason"]; ok {
			errStr = buffer["reason"].(string)
		}
		self.logger.Error(self.logCat, "Persona Auth Failed",
			util.Fields{"error": errStr,
				"buffer": fmt.Sprintf("%+v", buffer)})
		return "", "", ErrAuthorization
	}

	// extract the email
	if email, ok = buffer["email"].(string); !ok {
		self.logger.Error(self.logCat, "No email found in assertion",
			util.Fields{"assertion": fmt.Sprintf("%+v", buffer)})
		return "", "", ErrAuthorization
	}
	// and the userid, generating one if need be.
	if userid, ok = buffer["userid"].(string); !ok {
		hasher := sha256.New()
		hasher.Write([]byte(email))
		userid = hex.EncodeToString(hasher.Sum(nil))
	}
	return userid, email, nil
}

// get the user id from the session, or the assertion.
func (self *Handler) getUser(req *http.Request) (userid string, user string, err error) {
	useridc, err := req.Cookie("user")
	if err == http.ErrNoCookie {
		var auth string
		if auth = req.FormValue("assertion"); auth == "" {
			return "", "", ErrAuthorization
		}
		userid, user, err = self.verifyAssertion(auth)
		if err != nil {
			return "", "", ErrAuthorization
		}
	} else {

		if err != nil {
			return "", "", ErrAuthorization
		}
	}
	// Nothing in the session,
	var auth string
	if auth = req.FormValue("assertion"); auth == "" {
		return "", "", ErrAuthorization
	}
	userid, user, err = self.verifyAssertion(auth)
	if err != nil {
		return "", "", ErrAuthorization
	}
	return userid, user, nil
}

// set the user info into the session
func (self *Handler) getSessionInfo(req *http.Request) (session *sessionInfo, err error) {
	// Get this from the session?
	dev := getDevFromUrl(req.URL)
	userid, _, err := self.getUser(req)
	if err != nil {
		self.logger.Error("handler", "Could not get user",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	session = &sessionInfo{
		UserId:   userid,
		DeviceId: dev}
	return
}

// log the device's position reply
func (self *Handler) updatePage(devId string, args map[string]interface{}, logPosition bool) (err error) {
	var location storage.Position
	var locked bool

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		return err
	}
	defer store.Close()

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
		case "ti":
			location.Time = int64(arg.(float64))
		case "ha":
			locked = isTrue(arg)
			location.Lockable = !locked
			if err = store.SetDeviceLockable(devId, !locked); err != nil {
				return err
			}
		}
	}
	if logPosition {
		if err = store.SetDeviceLocation(devId, location); err != nil {
			return err
		}
		// because go sql locking.
		store.GcPosition(devId)
	}
	if client, ok := Clients[devId]; ok {
		js, _ := json.Marshal(location)
		client.Write(js)
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
		store, err := storage.Open(self.config, self.logger, self.metrics)
		if err != nil {
			self.logger.Error(self.logCat, "Could not open database",
				util.Fields{"error": err.Error()})
			return err
		}
		defer store.Close()
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

//Handler Public Functions

func NewHandler(config *util.MzConfig, logger *util.HekaLogger, metrics *util.Metrics) *Handler {
	store, err := storage.Open(config, logger, metrics)
	if err != nil {
		logger.Error("Handler", "Could not open database",
			util.Fields{"error": err.Error()})
		return nil
	}
	defer store.Close()

	// Initialize the data store once. This creates tables and
	// applies required changes.
	store.Init()

	return &Handler{config: config,
		logger:  logger,
		logCat:  "handler",
		metrics: metrics}
}

// Register a new device
func (self *Handler) Register(resp http.ResponseWriter, req *http.Request) {

	var buffer = util.JsMap{}
	var userid string
	var user string
	var pushUrl string
	var deviceid string
	var secret string
	var accepts string
	var lockable bool
	var err error

	self.logCat = "handler:Register"

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	defer store.Close()

	buffer, err = parseBody(req.Body)
	if err != nil {
		http.Error(resp, "No body", http.StatusBadRequest)
	} else {
		if assertion, ok := buffer["assert"].(string); !ok {
			self.logger.Error(self.logCat, "Missing assertion", nil)
			http.Error(resp, "Unauthorized", 401)
			return
		} else {
			userid, user, err = self.verifyAssertion(assertion)
			if err != nil || userid == "" {
				http.Error(resp, "Unauthorized", 401)
			}
			self.logger.Debug(self.logCat, "Got user "+userid, nil)
			user = strings.SplitN(user, "@", 2)[0]
		}

		if val, ok := buffer["pushurl"]; !ok || val == nil || len(val.(string)) == 0 {
			self.logger.Error(self.logCat, "Missing SimplePush url", nil)
			http.Error(resp, "Bad Data", 400)
			return
		} else {
			pushUrl = val.(string)
		}
		//ALWAYS generate a new secret on registration!
		secret = GenNonce(16)
		if val, ok := buffer["deviceid"]; !ok {
			deviceid, err = util.GenUUID4()
		} else {
			deviceid = strings.Map(deviceIdFilter, val.(string))
            if len(deviceid) > 32 {
                deviceid = deviceid[:32]
            }
		}
		if val, ok := buffer["has_passcode"]; !ok {
			lockable = true
		} else {
			lockable, err = strconv.ParseBool(val.(string))
			if err != nil {
				lockable = false
			}
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

		// create the new device record
		var devId string
		if devId, err = store.RegisterDevice(
			userid,
			storage.Device{
				ID:       deviceid,
				Name:     user,
				Secret:   secret,
				PushUrl:  pushUrl,
				Lockable: lockable,
				Accepts:  accepts,
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
	reply := fmt.Sprintf("{\"deviceid\":\"%s\", \"secret\":\"%s\"}",
		self.devId,
		secret)
	resp.Write([]byte(reply))
	return
}

// Handle the Cmd response from the device and pass next command if available.
func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
	var err error
	var l int

    fmt.Printf("#### URL: %s\n", req.URL)
	self.logCat = "handler:Cmd"
	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	defer store.Close()

	resp.Header().Set("Content-Type", "application/json")
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
				"Cmd:Unknown device requesting cmd",
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
		// Remote Hawk
		rhawk := Hawk{logger: self.logger}
		// Local Hawk
		lhawk := Hawk{logger: self.logger}
		// Get the remote signature from the header
		err = rhawk.ParseAuthHeader(req, self.logger)
		if err != nil {
			self.logger.Error(self.logCat, "Could not parse Hawk header",
				util.Fields{"error": err.Error()})
			http.Error(resp, "Unauthorized", 401)
			return
		}

		// Generate the comparator signature from what we know.
		lhawk.Nonce = rhawk.Nonce
		lhawk.Time = rhawk.Time
		//lhawk.Hash = rhawk.Hash

		err = lhawk.GenerateSignature(req, rhawk.Extra, string(body),
			devRec.Secret)
		if err != nil {
			self.logger.Error(self.logCat, "Could not verify sig",
				util.Fields{"error": err.Error()})
			http.Error(resp, "Unauthorized", 401)
			return
		}
		// Do they match?
		if !lhawk.Compare(rhawk.Signature) {
			self.logger.Error(self.logCat, "Cmd:Invalid Hawk Signature",
				util.Fields{
					"expecting": lhawk.Signature,
					"got":       rhawk.Signature,
				})
			http.Error(resp, "Unauthorized", 401)
			return
		}
	}
	// Do the command.
	self.logger.Info(self.logCat, "Handling cmd response from device",
		util.Fields{
			"cmd":    string(body),
			"length": fmt.Sprintf("%d", l),
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
			c := strings.ToLower(string(cmd[0]))
			if !strings.Contains(devRec.Accepts, c) {
				self.logger.Warn(self.logCat, "Unacceptable Command",
					util.Fields{"unacceptable": c,
						"acceptable": devRec.Accepts})
				continue
			}
			self.metrics.Increment("cmd.received." + string(c))
			switch c {
			case "l", "r", "m", "e":
                //lock, ring, message, erase
				err = store.Touch(deviceId)
				self.updatePage(deviceId,
					args.(map[string]interface{}), false)
			case "h":
                // "has lock code"
				argl := make(replyType)
				argl[string(cmd)] = isTrue(args)
				self.updatePage(deviceId, argl, false)
			case "t":
				// track
				err = self.updatePage(deviceId,
					args.(map[string]interface{}), true)
				// store tracking info.
			case "q":
				// User has quit, nuke what we know.
				if self.config.GetFlag("cmd.q.allow") {
					err = store.DeleteDevice(deviceId)
				}
			}
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error handling command",
					util.Fields{"error": err.Error(),
						"command": string(cmd),
						"device":  deviceId,
						"args":    fmt.Sprintf("%v", args)})
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
	c := strings.ToLower(string(cmd[0]))
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
	switch c {
	case "l":
		if v, ok = rargs["c"]; ok {
			max, err := strconv.ParseInt(self.config.Get("cmd.c.max", "9999"),
				10, 64)
			if err != nil {
				max = 9999
			}
			vs := v.(string)
			rargs["c"] = self.rangeCheck(
				strings.Map(digitsOnly, vs[:minInt(4, len(vs))]),
				0,
				max)
		}
		if v, ok = rargs["m"]; ok {
			vs := v.(string)
			rargs["m"] = strings.Map(asciiOnly,
				vs[:minInt(100, len(vs))])
		}
	case "r", "t":
		if v, ok = rargs["d"]; ok {
			vs := ""
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
			util.Fields{"command": string(cmd),
				"device": deviceId,
				"args":   fmt.Sprintf("%v", rargs)})
		return http.StatusBadRequest, errors.New("\"Invalid Command\"")
	}
	fixed, err := json.Marshal(storage.Unstructured{c: rargs})
	if err != nil {
		// Log the error
		self.logger.Error(self.logCat, "Error handling command",
			util.Fields{"error": err.Error(),
				"command": string(cmd),
				"device":  deviceId,
				"args":    fmt.Sprintf("%v", rargs)})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}
	defer store.Close()

	err = store.StoreCommand(deviceId, string(fixed))
	if err != nil {
		// Log the error
		self.logger.Error(self.logCat, "Error storing command",
			util.Fields{"error": err.Error(),
				"command": string(cmd),
				"device":  deviceId,
				"args":    fmt.Sprintf("%v", args)})
		return http.StatusServiceUnavailable, errors.New("\"Server Error\"")
	}
	// trigger the push
	self.metrics.Increment("cmd.store." + c)
	self.metrics.Increment("push.send")
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

	rep := make(replyType)

	self.logCat = "handler:Queue"

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	defer store.Close()

	resp.Header().Set("Content-Type", "application/json")
	deviceId := getDevFromUrl(req.URL)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	userId, _, err := self.getUser(req)
	if err != nil {
		self.logger.Error(self.logCat, "No userid", nil)
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if userId == "" {
		self.logger.Error(self.logCat, "No userid", nil)
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
		http.Error(resp, "Unauthorized", 401)
		return
	}

	devRec, err := store.GetDeviceInfo(deviceId)
	if err != nil || devRec == nil {
		fields := util.Fields{"deviceId": deviceId}
		if err != nil {
			fields["error"] = err.Error()
		}
		if devRec != nil {
			fields["devRec"] = devRec.ID
		}
		self.logger.Error(self.logCat, "Could not get userid", fields)
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if devRec.User != userId {
		self.logger.Error(self.logCat, "Unauthorized device",
			util.Fields{"devrec": devRec.User,
				"userid": userId})
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if devRec == nil {
		self.logger.Error(self.logCat,
			"Queue:User requested unknown device",
			util.Fields{
				"deviceId": deviceId,
				"userId":   userId})
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
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
	repl, _ := json.Marshal(rep)
	self.metrics.Increment("cmd.queued.rest")
	resp.Write(repl)
}

// user login functions
func (self *Handler) Index(resp http.ResponseWriter, req *http.Request) {
	/* Handle a user login to the web UI
	 */

	self.logCat = "handler:Index"
	// This should be handled by an nginx rule.
	if strings.Contains(req.URL.Path, "/static/") {
		if strings.Contains(req.URL.Path, "..") {
			return
		}
		body, err := ioutil.ReadFile("." + req.URL.Path)
		if err == nil {
			resp.Write(body)
		}
		return
	}
	var data struct {
		ProductName string
		UserId      string
		MapKey      string
		DeviceList  []storage.DeviceList
		Device      *storage.Device
		Host        map[string]string
	}

	var err error

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	defer store.Close()

	// Get this from the config file?
	data.ProductName = self.config.Get("productname", "Find My Device")

	data.MapKey = self.config.Get("mapbox.key", "")

	// host information (for websocket callback)
	data.Host = make(map[string]string)
	data.Host["Hostname"] = self.config.Get("ws_hostname", "localhost")

	// get the cached session info (if present)
	// will also resolve assertions and other bits to get user and dev info.
	sessionInfo, err := self.getSessionInfo(req)
	if err == nil {
		// we have user info, use it.
		data.UserId = sessionInfo.UserId
		if sessionInfo.DeviceId == "" {
			data.DeviceList, err = store.GetDevicesForUser(data.UserId)
			if err != nil {
				self.logger.Error(self.logCat, "Could not get user devices",
					util.Fields{"error": err.Error(),
						"user": data.UserId})
			}
			if len(data.DeviceList) == 1 {
				sessionInfo.DeviceId = (data.DeviceList[0]).ID
				data.DeviceList = nil
			}
		}
		if sessionInfo.DeviceId != "" {
			data.Device, err = store.GetDeviceInfo(sessionInfo.DeviceId)
			if err != nil {
				self.logger.Error(self.logCat, "Could not get device info",
					util.Fields{"error": err.Error(),
						"user": data.UserId})
				if file, err := ioutil.ReadFile("static/error.html"); err == nil {
					resp.Write(file)
				}
				return
			}
			data.Device.PreviousPositions, err = store.GetPositions(sessionInfo.DeviceId)
			if err != nil {
				self.logger.Error(self.logCat,
					"Could not get device's position information",
					util.Fields{"error": err.Error(),
						"user":   data.UserId,
						"device": sessionInfo.DeviceId})
				return
			}
		}
	}

	// render the page from the template
	tmpl, err := template.New("index.html").ParseFiles("static/app/index.html")
	if err != nil {
		self.logger.Error(self.logCat, "Could not display index page",
			util.Fields{"error": err.Error(),
				"user": data.UserId})
		if file, err := ioutil.ReadFile("static/error.html"); err == nil {
			resp.Write(file)
		}
		return
	}
	if sessionInfo != nil {
		setSessionInfo(resp, sessionInfo)
	} else {
		http.SetCookie(resp, &http.Cookie{Name: "user", MaxAge: -1})
	}
	err = tmpl.Execute(resp, data)
	if err != nil {
		self.logger.Error(self.logCat, "Could not execute template",
			util.Fields{"error": err.Error()})
	}
	self.metrics.Increment("page.index")
	return
}

// Show the state of the user's devices.
func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
	// get session info
	self.logCat = "handler:State"

	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server error", 500)
		return
	}
	defer store.Close()

	sessionInfo, err := self.getSessionInfo(req)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}
	devInfo, err := store.GetDeviceInfo(sessionInfo.DeviceId)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}
	// add the user session cookie
	setSessionInfo(resp, sessionInfo)
	// display the device info...
	reply, err := json.Marshal(devInfo)
	if err == nil {
		resp.Write([]byte(reply))
	}
}

// Show the status of the program (For Load Balancers)
func (self *Handler) Status(resp http.ResponseWriter, req *http.Request) {
	self.logCat = "handler:Status"
	reply := replyType{
		"status":     "ok",
		"goroutines": runtime.NumGoroutine(),
		"version":    req.URL.Path[len("/status/"):],
	}
	rep, _ := json.Marshal(reply)
	resp.Write(rep)
}

// Handle requests for static content (should be an NGINX rule)
func (self *Handler) Static(resp http.ResponseWriter, req *http.Request) {
	/* This should be handled by something like an nginx rule
	 */
	http.ServeFile(resp, req, "./static/app/"+req.URL.Path)
}

// Display the current metrics as a JSON snapshot
func (self *Handler) Metrics(resp http.ResponseWriter, req *http.Request) {
	snapshot := self.metrics.Snapshot()

	resp.Header().Set("Content-Type", "application/json")
	reply, err := json.Marshal(snapshot)
	if err != nil {
		self.logger.Error(self.logCat, "Could not generate metrics report",
			util.Fields{"error": err.Error()})
		resp.Write([]byte("{}"))
		return
	}
	if reply == nil {
		reply = []byte("{}")
	}
	resp.Write(reply)
}

// Add a new trackable client.
func addClient(id string, sock *WWS) {
	defer muClient.Unlock()
	muClient.Lock()
	Clients[id] = sock
}

// remove a trackable client
func rmClient(id string) {
	defer muClient.Unlock()
	muClient.Lock()
	if _, ok := Clients[id]; ok {
		delete(Clients, id)
	}
}

// Handle Websocket processing.
func (self *Handler) WSSocketHandler(ws *websocket.Conn) {
	self.logCat = "handler:Socket"
	store, err := storage.Open(self.config, self.logger, self.metrics)
	if err != nil {
		self.logger.Error(self.logCat, "Could not open database",
			util.Fields{"error": err.Error()})
		return
	}
	defer store.Close()

	self.devId = getDevFromUrl(ws.Request().URL)
	devRec, err := store.GetDeviceInfo(self.devId)
	if err != nil {
		self.logger.Error(self.logCat, "Invalid Device for socket",
			util.Fields{"error": err.Error(),
				"devId": self.devId})
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
				log.Printf("Socket Unknown Error: %s\n", r.(error).Error())
			}
		}
	}(sock.Logger)

	// get the device id from the localAddress:
	Url, err := url.Parse(ws.LocalAddr().String())
	if err != nil {
		self.logger.Error(self.logCat, "Unparsable URL for websocket",
			util.Fields{"error": err.Error()})
		return
	}
	elements := strings.Split(Url.Path, "/")
	var deviceId string
	if len(elements) < 3 {
		self.logger.Error(self.logCat, "No deviceID found",
			util.Fields{"error": err.Error(),
				"path": Url.Path})
		return
	}
	deviceId = elements[3]
	// Kill the old client.
	if client, ok := Clients[deviceId]; ok {
		client.Quit = true
	}

	self.metrics.Increment("page.socket")
	addClient(deviceId, sock)
	sock.Run()
	self.metrics.Decrement("page.socket")
	self.metrics.Timer("page.socket", time.Now().Unix()-sock.Born.Unix())
	rmClient(deviceId)
}
