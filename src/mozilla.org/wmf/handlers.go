package wmf

import (
	"mozilla.org/util"
	"mozilla.org/wmf/storage"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
)

type Handler struct {
	config  util.JsMap
	logger  *util.HekaLogger
	store   *storage.Storage
	devId   string
	logCat  string
	accepts []string
	hawk    *Hawk
}

type reply_t map[string]interface{}

type sessionInfo struct {
	UserId   string
	DeviceId string
}

type ui_cmd struct {
	c    string
	args map[string]interface{}
}

var InvalidReplyErr = errors.New("Invalid Command Response")
var AuthorizationErr = errors.New("Needs Authorization")

//filters
func digitsOnly(r rune) rune {
	switch {
	case r >= '0' && r <= '9':
		return r
	default:
		return -1
	}
}

func asciiOnly(r rune) rune {
	switch {
	case r >= 32 && r <= 255:
		return r
	default:
		return -1
	}
}

// parse a body and return the JSON
func parseBody(rbody io.ReadCloser) (rep util.JsMap, err error) {
	var body []byte
	rep = util.JsMap{}
	defer rbody.Close()
	if body, err = ioutil.ReadAll(rbody.(io.Reader)); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(body, &rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// Take an interface value and return if it's true or not.
func isTrue(val interface{}) bool {
	switch val.(type) {
	case string:
		flag, _ := strconv.ParseBool(val.(string))
		return flag
	case bool:
		return val.(bool)
	case int64:
		return val.(int64) != 0
	default:
		return false
	}
}

func minInt(x, y int) int {
	// There's no built in min function.
	// awesome.
	if x < y {
		return x
	}
	return y
}

//Handler private functions

// verify a Persona assertion using the config values
func (self *Handler) verifyAssertion(assertion string) (userid, email string, err error) {
	var ok bool
	if util.MzGetFlag(self.config, "auth.disabled") {
		return "user1", "user@example.com", nil
	}
	ver_url := util.MzGet(self.config, "persona.validater_url", "https://verifier.login.persona.org/verify")
	audience := util.MzGet(self.config, "persona.audience",
		"http://localhost:8080")
	res, err := http.PostForm(ver_url, url.Values{
		"assertion": {assertion},
		"audience":  {audience}})
	if err != nil {
		self.logger.Error(self.logCat, "Persona verification failed",
			util.Fields{"error": err.Error()})
		return "", "", AuthorizationErr
	}
	buffer, err := parseBody(res.Body)
	if isOk, ok := buffer["status"]; !ok || isOk != "okay" {
		self.logger.Error(self.logCat, "Persona Auth Failed",
			util.Fields{"error": err.Error()})
		return "", "", AuthorizationErr
	}
	if email, ok = buffer["email"].(string); !ok {
		self.logger.Error(self.logCat, "No email found in assertion",
			util.Fields{"assertion": fmt.Sprintf("%+v", buffer)})
		return "", "", AuthorizationErr
	}
	if userid, ok = buffer["userid"].(string); !ok {
		hasher := sha256.New()
		hasher.Write([]byte(email))
		userid = hex.EncodeToString(hasher.Sum(nil))
	}
	return userid, email, nil
}

// get the device id from the URL path
func (self *Handler) getDevFromUrl(req *http.Request) (devId string) {
	elements := strings.Split(req.URL.Path, "/")
	return elements[len(elements)-1]
}

// get the user id info from the session. (userid/devid)
func (self *Handler) setSessionInfo(resp http.ResponseWriter, session *sessionInfo) (err error) {
	cookie := http.Cookie{Name: "user",
		Value: session.UserId,
		Path:  "/"}
	http.SetCookie(resp, &cookie)
	return err
}

// get the user id from the session, or the assertion.
func (self *Handler) getUser(req *http.Request) (userid string, err error) {
	// remove this!
	self.logger.Info(self.logCat, "### USING DUMMY", nil)
	req.AddCookie(&http.Cookie{Name: "user",
		Value: "user1",
		Path:  "/"})
	//TODO: accept Auth before cookie?

	useridc, err := req.Cookie("user")
	if err == http.ErrNoCookie {
		var auth string
		if auth = req.Header.Get("Authorization"); auth != "" {
			return "", AuthorizationErr
		}
		fmt.Printf("Verifying Assertion %s", auth)
		userid, _, err = self.verifyAssertion(auth)
		if err != nil {
			return "", AuthorizationErr
		}
	} else {
		if err != nil {
			return "", AuthorizationErr
		}
		userid = useridc.Value
	}
	return userid, nil
}

// set the user info into the session
func (self *Handler) getSessionInfo(req *http.Request) (session *sessionInfo, err error) {
	// Get this from the session?
	dev := self.getDevFromUrl(req)
	user, err := self.getUser(req)
	if err != nil {
		self.logger.Error("handler", "Could not get user",
			util.Fields{"error": err.Error()})
		return nil, err
	}
	session = &sessionInfo{
		UserId:   user,
		DeviceId: dev}
	return
}

// log the device's position reply
func (self *Handler) logPosition(devId string, args map[string]interface{}) (err error) {
	var location storage.Position
	var locked bool

	for key, arg := range args {
		switch k := strings.ToLower(key[:2]); k {
		case "la":
			location.Latitude = arg.(float64)
		case "lo":
			location.Longitude = arg.(float64)
		case "al":
			location.Altitude = arg.(float64)
		case "ti":
			location.Time = int64(arg.(float64))
		case "ke":
			locked = isTrue(arg)
			if err = self.store.SetDeviceLocked(devId, locked); err != nil {
				return err
			}
		}
	}
	if err = self.store.SetDeviceLocation(devId, location); err != nil {
		return err
	}
	// because go sql locking.
	self.store.GcPosition(devId)
	return nil
}

// log the cmd reply from the device.
func (self *Handler) logReply(devId, cmd string, args reply_t) (err error) {
	// verify state and store it
	if v, ok := args["ok"]; !ok {
		return InvalidReplyErr
	} else {
		if !isTrue(v) {
			if e, ok := args["error"]; ok {
				return errors.New(e.(string))
			} else {
				return errors.New("Unknown error")
			}
		}
		// log the state? (Device is currently cmd-ing)?
		err = self.store.LogState(devId, string(cmd[0]))
	}
	return err
}

//Handler Public Functions

func NewHandler(config util.JsMap, logger *util.HekaLogger, store *storage.Storage) *Handler {
	return &Handler{config: config,
		logger: logger,
		logCat: "handler",
		hawk:   &Hawk{logger: logger},
		store:  store}
}

func (self *Handler) Register(resp http.ResponseWriter, req *http.Request) {
	/*register a new device
	 */

	var buffer util.JsMap = util.JsMap{}
	var userid string
	var pushUrl string
	var deviceid string
	var secret string
	var accepts string
	var lockable bool
	var ok bool

	self.logCat = "handler:Register"

	buffer, err := parseBody(req.Body)
	if err != nil {
		http.Error(resp, "No body", http.StatusBadRequest)
	} else {
		if assertion, ok := buffer["assert"].(string); !ok {
			self.logger.Error(self.logCat, "Missing assertion", nil)
			http.Error(resp, "Unauthorized", 401)
			return
		} else {
			userid, _, err = self.verifyAssertion(assertion)
			if err != nil {
				http.Error(resp, "Unauthorized", 401)
			}
		}

		if _, ok = buffer["pushurl"]; !ok {
			self.logger.Error(self.logCat, "Missing SimplePush url", nil)
			http.Error(resp, "Bad Data", 400)
			return
		} else {
			pushUrl = buffer["pushurl"].(string)
		}
		if _, ok = buffer["secret"]; !ok {
			// Return this nonce as part of the reg reply
			secret = GenNonce(16)
		} else {
			secret = buffer["secret"].(string)
		}
		if _, ok = buffer["deviceid"]; !ok {
			deviceid, err = util.GenUUID4()
		} else {
			deviceid = buffer["deviceid"].(string)
		}
		if _, ok = buffer["lockable"]; !ok {
			lockable = true
		} else {
			lockable, err = strconv.ParseBool(buffer["lockable"].(string))
			if err != nil {
				lockable = false
			}
		}
		if k, ok := buffer["accepts"]; ok {
			// collapse the array to a string
			if l := len(k.([]interface{})); l > 0 {
				acc := make([]byte, l)
				for n, ke := range k.([]interface{}) {
					acc[n] = ke.(string)[0]
				}
				accepts = strings.ToLower(string(acc))
			}
		}
		if len(accepts) == 0 {
			accepts = "elrt"
		}

		// create the new device record
		if devId, err := self.store.RegisterDevice(
			userid,
			storage.Device{
				ID:       deviceid,
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

	resp.Write([]byte(fmt.Sprintf("{\"id\":\"%s\", \"secret\":\"%s\"}",
		self.devId,
		secret)))
	return
}

func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
	/* Log response and Pass the latest command off to the device.
	 */
	var err error
	var l int

	self.logCat = "handler:Cmd"
	deviceId := self.getDevFromUrl(req)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}

	devRec, err := self.store.GetDeviceInfo(deviceId)
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
	//validate the Hawk header
	if util.MzGetFlag(self.config, "hawk.disabled") == false {
		hawk, signature, err := ParseHawkAuthHeader(req, self.logger)
		if err != nil {
			self.logger.Error(self.logCat, "Could not parse Hawk header",
				util.Fields{"error": err.Error()})
			http.Error(resp, "Unauthorized", 401)
			return
		}
		vsig, err := hawk.GenerateSignature(req, "", devRec.Secret)
		if err != nil {
			self.logger.Error(self.logCat, "Could not verify sig",
				util.Fields{"error": err.Error()})
			http.Error(resp, "Unauthorized", 401)
			return
		}
		if signature != vsig {
			self.logger.Error(self.logCat, "Cmd:Invalid Hawk Signature",
				util.Fields{
					"expecting": vsig,
					"got":       signature,
				})
			http.Error(resp, "Unauthorized", 401)
			return
		}
	}
	//decode the body
	var body = make([]byte, req.ContentLength)
	l, err = req.Body.Read(body)
	if err != nil {
		self.logger.Error(self.logCat, "Could not read body",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Invalid", 400)
		return
	}
	self.logger.Info(self.logCat, "Handling cmd",
		util.Fields{
			"cmd": string(body),
			"l":   fmt.Sprintf("%d", l),
		})
	if l > 0 {
		reply := make(reply_t)
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
			switch c {
			case "l", "r", "m", "e":
				err = self.store.StoreCommand(deviceId, string(body))
			case "t":
				// track
				err = self.logPosition(deviceId, args.(map[string]interface{}))
				// store tracking info.
			}
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error handling command",
					util.Fields{"error": err.Error(),
						"command": string(cmd),
						"device":  deviceId,
						"args":    fmt.Sprintf("%v", args)})
				http.Error(resp,
					"Server Error",
					http.StatusServiceUnavailable)
				return
			}
		}
	}

	// reply with pending commands
	//
	cmd, err := self.store.GetPending(deviceId)
	var output []byte = []byte(cmd)
	if err != nil {
		self.logger.Error(self.logCat, "Could not send commands",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", http.StatusServiceUnavailable)
	}
	hasher := sha256.New()
	hasher.Write(output)
	extra := hex.EncodeToString(hasher.Sum(nil))
	authHeader := self.hawk.AsHeader(req, devRec.User, extra, devRec.Secret, "")
	resp.Header().Add("Authorization", authHeader)
	resp.Write(output)
}

func (self *Handler) Queue(resp http.ResponseWriter, req *http.Request) {
	/* Queue commands for the device.
	 */
	var err error
	var l int

	self.logCat = "handler:Queue"
	deviceId := self.getDevFromUrl(req)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	userId, err := self.getUser(req)
	if err != nil {
		self.logger.Error(self.logCat, "No userid", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	if userId == "" {
		http.Error(resp, "Unauthorized", 401)
		return
	}

	devRec, err := self.store.GetDeviceInfo(deviceId)
    if devRec.User != userId {
        http.Error(resp, "Unauthorized", 401)
        return
    }
	if devRec == nil {
		self.logger.Error(self.logCat,
			"Queue:User requested unknown device",
			util.Fields{
				"deviceId": deviceId,
                "userId": userId})
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
	l, err = req.Body.Read(body)
	if err != nil {
		self.logger.Error(self.logCat, "Could not read body",
			util.Fields{"error": err.Error()})
		http.Error(resp, "Invalid", 400)
		return
	}
	self.logger.Info(self.logCat, "Handling cmd",
		util.Fields{
			"cmd": string(body),
			"l":   fmt.Sprintf("%d", l),
		})
	if l > 0 {
		reply := make(reply_t)
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
			// sanitize values.
			var v interface{}
			var ok bool
			c := strings.ToLower(string(cmd[0]))
			if !strings.Contains(devRec.Accepts, c) {
				// skip unacceptable command
				self.logger.Warn(self.logCat, "Agent does not accept command",
					util.Fields{"unacceptable": c,
						"acceptable": devRec.Accepts})
				continue
			}
			rargs := args.(map[string]interface{})
			switch c {
			case "l":
				if v, ok = rargs["c"]; ok {
					vs := v.(string)
					rargs["c"] = strings.Map(digitsOnly, vs[:minInt(4, len(vs))])
				}
				if v, ok = rargs["m"]; ok {
					vs := v.(string)
					rargs["m"] = strings.Map(asciiOnly, vs[:minInt(100, len(vs))])
				}
			case "r", "t":
				if v, ok = rargs["d"]; ok {
					vs := v.(string)
					rargs["d"] = strings.Map(digitsOnly, vs)
				}
			case "e":
				rargs = storage.Unstructured{}
			default:
				http.Error(resp, "Invalid Command", 400)
				return
			}
			fixed, err := json.Marshal(storage.Unstructured{c: rargs})
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error handling command",
					util.Fields{"error": err.Error(),
						"command": string(cmd),
						"device":  deviceId,
						"args":    fmt.Sprintf("%v", rargs)})
				http.Error(resp, "Server Error", http.StatusServiceUnavailable)
			}
			err = self.store.StoreCommand(deviceId, string(fixed))
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error storing command",
					util.Fields{"error": err.Error(),
						"command": string(cmd),
						"device":  deviceId,
						"args":    fmt.Sprintf("%v", args)})
				http.Error(resp, "Server Error", http.StatusServiceUnavailable)
			}
		}
	}
	resp.Write([]byte("{}"))
}

// user login functions
func (self *Handler) Index(resp http.ResponseWriter, req *http.Request) {
	/* Handle a user login to the web UI
	 */

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
	self.logCat = "handler:Index"
	var data struct {
		ProductName string
		UserId      string
		DeviceList  []storage.DeviceList
		Device      *storage.Device
	}

	data.ProductName = "Where's My Fox"
	sessionInfo, err := self.getSessionInfo(req)
	if err != nil {
		self.logger.Error(self.logCat, "Could not get session info",
			util.Fields{"error": err.Error()})
		if file, err := ioutil.ReadFile("static/error.html"); err == nil {
			resp.Write(file)
		}
		return
	}
	data.UserId = sessionInfo.UserId
	tmpl, err := template.New("index.html").ParseFiles("static/index.html")
	if err != nil {
		// TODO: display error
		self.logger.Error(self.logCat, "Could not display index page",
			util.Fields{"error": err.Error(),
				"user": data.UserId})
		if file, err := ioutil.ReadFile("static/error.html"); err == nil {
			resp.Write(file)
		}
		return
	}
	if sessionInfo.DeviceId == "" {
		data.DeviceList, err = self.store.GetDevicesForUser(data.UserId)
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
		data.Device, err = self.store.GetDeviceInfo(sessionInfo.DeviceId)
		if err != nil {
			self.logger.Error(self.logCat, "Could not get device info",
				util.Fields{"error": err.Error(),
					"user": data.UserId})
			if file, err := ioutil.ReadFile("static/error.html"); err == nil {
				resp.Write(file)
			}
			return
		}
	}
	err = tmpl.Execute(resp, data)
	if err != nil {
		self.logger.Error(self.logCat, "Could not execute query",
			util.Fields{"error": err.Error()})
	}
	return
}

func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
	/* Show the state of the user's devices.
	 */
	// get session info
	self.logCat = self.logCat + ":State"
	sessionInfo, err := self.getSessionInfo(req)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}
	devInfo, err := self.store.GetDeviceInfo(sessionInfo.DeviceId)
	if err != nil {
		http.Error(resp, err.Error(), 500)
		return
	}
	// add the user session cookie
	self.setSessionInfo(resp, sessionInfo)
	// display the device info...
	reply, err := json.Marshal(devInfo)
	if err == nil {
		resp.Write([]byte(reply))
	}
}

func (self *Handler) Status(resp http.ResponseWriter, req *http.Request) {
	/* Show program status
	 */
	self.logCat = "handler:Status"
	resp.Write([]byte(fmt.Sprintf("%v", req.URL.Path[len("/status/"):])))
	resp.Write([]byte("OK"))
}

func (self *Handler) Static(resp http.ResponseWriter, req *http.Request) {
	/* This should be handled by something like an nginx rule
	 */
	sl := len("/static/")
	if len(req.URL.Path) > sl {
		http.ServeFile(resp, req, "./static/"+req.URL.Path[sl:])
	}
}
