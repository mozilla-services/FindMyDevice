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
	config util.JsMap
	logger *util.HekaLogger
	store  *storage.Storage
	devId  string
	logCat string
}

type reply_t map[string]interface{}

type sessionInfo struct {
	UserId   string
	DeviceId string
}

var InvalidReplyErr = errors.New("Invalid Command Response")
var AuthorizationErr = errors.New("Needs Authorization")

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

// verify a Persona assertion using the config values
func (self *Handler) verifyAssertion(assertion string) (userid, email string, err error) {
	var ok bool
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
    fmt.Printf("%d %v", len(elements), elements)
	if len(elements) > 3 {
		return elements[3]
	}
	return ""
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
	self.logger.Info(self.logCat, "####### USING DUMMY", nil)
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
	if dev == "" {
		dev = "test1"
	}
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

// log the device's position reply
func (self *Handler) logPosition(devId string, args reply_t) (err error) {
	var location storage.Position
	var locked bool

	for key, arg := range args {
		switch k := strings.ToLower(key[:2]); k {
		case "la":
			location.Latitude = arg.(float32)
		case "lo":
			location.Longitude = arg.(float32)
		case "al":
			location.Altitude = arg.(float32)
		case "ti":
			location.Time = arg.(int32)
		case "ke":
			locked = isTrue(arg)
			if err = self.store.SetDeviceLocked(self.devId, locked); err != nil {
				return err
			}
		}
	}
	if err = self.store.SetDeviceLocation(self.devId, location); err != nil {
		return err
	}
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
	var lockable bool
	var ok bool

    // TODO: Handle map of "allowed commands" from client?
	self.logCat = "handler:Register"

	buffer, err := parseBody(req.Body)
	if err != nil {
		http.Error(resp, "No body", http.StatusBadRequest)
	} else {
		if assertion, ok := buffer["assertion"].(string); !ok {
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
			self.logger.Error(self.logCat, "Missing HAWK secret", nil)
			http.Error(resp, "Bad Data", 400)
			return
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
		// create the new device record
		if devId, err := self.store.RegisterDevice(userid, storage.Device{
			ID:       deviceid,
			Secret:   secret,
			PushUrl:  pushUrl,
			Lockable: lockable,
		}); err != nil {
			self.logger.Error(self.logCat, "Error storing data", nil)
			http.Error(resp, "Server error", 500)
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
	return

}

func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
	/* Pass the latest command off to the device.
	 */
	var body []byte
	var err error
	var l int

	self.logCat = "handler:Cmd"
	deviceId := self.getDevFromUrl(req)
	if deviceId == "" {
		self.logger.Error(self.logCat, "Invalid call (No device id)", nil)
		http.Error(resp, "Unauthorized", 401)
		return
	}
	// get the record for the deviceID
	if self.store.ValidateDevice(deviceId) == false {
		self.logger.Error(self.logCat, "Cmd:Unknown device requesting cmd",
			util.Fields{
				"deviceId": deviceId})
		http.Error(resp, "Unauthorized", 401)
		return
	}
	//decode the body
	l, err = req.Body.Read(body)
	if l > 0 {
		reply := make(reply_t)
		merr := json.Unmarshal(body, reply)
		if merr != nil {
			self.logger.Error(self.logCat, "Could not unmarshal data", util.Fields{
				"error": merr.Error(),
				"body":  string(body)})
			http.Error(resp, "Server Error", 500)
			return
		}

		// handle command acks
		for cmd, args := range reply {
			c := strings.ToLower(string(cmd[0]))
			switch c {
			case "l", "r", "m", "e":
				err = self.logReply(deviceId, c, args.(reply_t))
			case "t":
				// track
				err = self.logPosition(deviceId, args.(reply_t))
				// store tracking info.
			}
			if err != nil {
				// Log the error
				self.logger.Error(self.logCat, "Error handling command",
					util.Fields{"error": err.Error(),
						"command": string(cmd),
						"device":  deviceId,
						"args":    fmt.Sprintf("%v", args)})
				http.Error(resp, "Server Error", http.StatusServiceUnavailable)
			}
		}
	}

	// reply with pending commands
	//
	cmd, err := self.store.GetPending(deviceId)
	if err == nil {
		jcmd, err := json.Marshal(cmd)
		if err != nil {
			self.logger.Error(self.logCat, "Error marshalling pending cmd",
				util.Fields{"error": err.Error(),
					"device": deviceId})
			http.Error(resp, "Server Error", http.StatusServiceUnavailable)
			return
		}
		resp.Write(jcmd)
	} else {
		self.logger.Error(self.logCat, "Could not send commands", util.Fields{"error": err.Error()})
		http.Error(resp, "Server Error", http.StatusServiceUnavailable)
	}
	resp.Write([]byte("{}"))

}

// user login functions
func (self *Handler) Index(resp http.ResponseWriter, req *http.Request) {
	/* Handle a user login to the web UI
	 */

    // This should be handled by an nginx rule.
    if strings.Contains(req.URL.Path,"/static/"){
        if strings.Contains(req.URL.Path,"..") {
            return
        }
        body, err :=ioutil.ReadFile("."+req.URL.Path)
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
	} else {
		data.Device, err = self.store.GetDeviceInfo(data.UserId,
			sessionInfo.DeviceId)
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
            util.Fields{"error":err.Error()})
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
	devInfo, err := self.store.GetDeviceInfo(sessionInfo.UserId,
		sessionInfo.DeviceId)
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

type ui_cmd struct {
    c string
    args map[string]interface{}
}

//filters
func digitsOnly(r rune) (rune) {
    switch{
        case r >='0' && r <='9':
            return r
        default:
            return -1
    }
}

func asciiOnly(r rune) (rune) {
    switch{
    case r>=32 && r <=255:
        return r
    default:
        return -1
    }
}

func (self *Handler)getCommand(req) (cmd ui_cmd, err error){
    err = req.ParseForm()
    if err != nil {
        self.log.Error(self.logCat, "Could not parse UI request",
            util.Fields{"error":err.Error()})
        return cmd, err
    }
    // filter "c" value against clients allowed commands
    cmdKey := req.FormValue("cmd")
    if cmdKey == "" {
        self.log.Error(self.logCat, "Missing c arg",
                util.Fields{"post": fmt.Sprintf("%+v",req.Form)})
        return cmd, InvalidReplyErr
    }
    ui_cmd.c = strings.ToLower(cmdKey[0])
    switch ui_cmd.c
        // validate the args based on command.
        args map[string]interface
        case "l": // Lock
            //get "c"ode, "m"essage and optional "n"umber
            args["c"] = strings.Map(digitsOnly, req.FormValue("c")[:4])
            args["m"] = strings.Map(asciiOnly, req.FormValue("m")[:100])
        case "r":
            //get "d"uration and "p"eriod
            args["d"],err1 := strconv.ParseInt(req.FormValue("d"),10,32)
            args["p"],err2 := strconv.ParseInt(req.FormValue("p"),10,32)
            if err1 != nil || err2 != nil {
                // badness
                return cmd, InvalidReplyErr
            }
        case "t":
            //get "d"uration and "p"eriod
        case "e":
            // confirm ?
        default:
            self.log.Error(self.logCat, "Invalid command specified",
                util.Fields{"post": fmt.Sprintf("%+v",req.Form)})
            return cmd, err
    }
    // record the command for pickup.
    // if there's a Push URL, hit it.
    // set the state?
}



func (self *Handler) SendCmd(resp http.ResponseWriter, req *http.Request) {
	/* queue a command to a device
	 */

	//TODO
    self.logCat = "handler:SendCmd"
    sessionInfo,err := self.getSessionInfo(req)
    if sessionInfo.UserId == "" {
        self.logger.Error(self.logCat, "Unauthorized", nil)
        http.Error(resp, "Unauthorized", 401)
        return
    }
    if sessionInfo.DeviceId == "" {
        self.logger.Error(self.logCat, "No device selected", nil)
        http.Error(resp, "No device selected", 400)
        return
    }
    // get the command object
    command := self.getCommand(req)

	// is the user logged in?
	// no, they fail
	// validate the command and args
	// add to device's queue

}

func (self *Handler) Status(resp http.ResponseWriter, req *http.Request) {
	/* Show program status
	 */
    self.logCat = "handler:Status"
	resp.Write([]byte(fmt.Sprintf("%v", req.URL.Path[len("/status/"):])))
	resp.Write([]byte("OK"))
}

func (self *Handler) Static(resp http.ResponseWriter, req *http.Request){
    /* This should be handled by something like an nginx rule
    */
    sl := len("/static/")
    if len(req.URL.Path) > sl {
        http.ServeFile(resp, req, "./static/"+req.URL.Path[sl:])
    }
}

