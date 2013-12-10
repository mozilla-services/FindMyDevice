package wmf

import (
    "mozilla.org/util"
    "mozilla.org/wmf/storage"

    "errors"
    "encoding/json"
    "encoding/hex"
    "crypto/sha256"
    "io"
    "io/ioutil"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "fmt"
    "html/template"

)

type Handler struct {
    config util.JsMap
    logger *util.HekaLogger
    store  *storage.Storage
    devId string
    logCat string
}

type reply_t map[string]interface{}

type sessionInfo struct {
    userId string
    deviceId string
}

var InvalidReplyErr = errors.New("Invalid Command Response")
var AuthorizationErr = errors.New("Needs Authorization")


// parse a body and return the JSON
func parseBody (rbody io.ReadCloser) (rep util.JsMap, err error) {
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
         "audience": {audience}})
     if err != nil {
         self.logger.Error(self.logCat, "Persona verification failed",
            util.Fields{"error": err.Error()})
         return "","", AuthorizationErr
     }
     buffer, err := parseBody(res.Body)
     if isOk, ok := buffer["status"]; !ok || isOk != "okay" {
         self.logger.Error(self.logCat, "Persona Auth Failed",
                util.Fields{"error": err.Error()})
         return "", "", AuthorizationErr
     }
     if email, ok = buffer["email"].(string); !ok {
         self.logger.Error(self.logCat, "No email found in assertion",
                util.Fields{"assertion": fmt.Sprintf("%v", buffer)})
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
    elements :=  strings.Split(req.URL.Path,"/")
    return elements[3]
}

// get the user id info from the session. (userid/devid)
func (self *Handler) setSessionInfo(resp http.ResponseWriter, session *sessionInfo) (err error){
    return http.SetCookie(resp, &http.Cookie{Name:"user",
        Value:sessionInfo.userId,
        Path:"/"})
}


// get the user id from the session, or the assertion.
func (self *Handler) getUser(req *http.Request) (userid string, err error) {
// remove this!
    fmt.Printf("####### USING DUMMY\n");
    req.AddCookie(&http.Cookie{Name:"user",
        Value:"user1",
        Path:"/"})
    //TODO: Auth before cookie?

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
func (self *Handler) getSessionInfo(req *http.Request) (session *sessionInfo, err error){
    // TODO get real values from the session
    //temp get the dev from the url
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
        userId:user,
        deviceId:dev}
   return
}

// Take an interface value and return if it's true or not.
func isTrue(val interface{}) (bool) {
    switch val.(type) {
    case string:
        flag,_ := strconv.ParseBool(val.(string))
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
        switch k := strings.ToLower(key[:2]);k {
        case "la":
            location.Latitude = arg.(float64)
        case "lo":
            location.Longitude = arg.(float64)
        case "al":
            location.Altitude = arg.(float64)
        case "ti":
            location.Time = arg.(int64)
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
func (self *Handler) logReply(devId, cmd string, args reply_t) (err error){
    // verify state and store it
    if v,ok := args["ok"]; !ok {
        return InvalidReplyErr
    } else {
        if (!isTrue(v)) {
            if e,ok := args["error"]; ok {
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

func NewHandler (config util.JsMap, logger *util.HekaLogger, store *storage.Storage) *Handler {
    return &Handler{ config: config,
        logger: logger,
        logCat: "handler",
        store: store}
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
            lockable= true
        } else {
            lockable, err = strconv.ParseBool(buffer["lockable"].(string))
            if err != nil {
                lockable = false
            }
        }
        // create the new device record
        if devId, err := self.store.RegisterDevice(userid, storage.Device{
            ID: deviceid,
            Secret: secret,
            PushUrl: pushUrl,
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
                "body": string(body)})
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
                    util.Fields{"error":err.Error(),
                                "command": string(cmd),
                                "device": deviceId,
                                "args": fmt.Sprintf("%v", args)})
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
        self.logger.Error(self.logCat, "Could not send commands", util.Fields{"error":err.Error()})
        http.Error(resp, "Server Error", http.StatusServiceUnavailable)
    }
    resp.Write([]byte("{}"))

}


// user login functions
func (self *Handler) Index(resp http.ResponseWriter, req *http.Request) {
    /* Handle a user login to the web UI
    */
    //TODO
    var deviceId string
    var data struct{ProductName string,
        UserId string,
        DeviceList []storage.DeviceList,
        Device storage.Device}

    data.ProjectName = "Where's My Fox"
    userId, err := self.getUser(req)
    tmpl := html.Template("index")
    t, err := tmpl.ParseFiles("static/index.html")
    if err != nil {
        // TODO: display error
    }
    sessionInfo, err := self.getSessionInfo(req)
    if sessionInfo.deviceId == "" || err != nil {
        data.DeviceList, err := self.store.GetDevicesForUser(userId)
        if err != nil {
            self.logger.Error(self.logCat, "Could not get user devices",
                util.Fields{"error", err.Error(),
                            "user", userId})
        }
    } else {
        data.Device, err := self.store.GetDeviceInfo(userId,
            sessionInfo.deviceId)
        if err != nil {
            // TODO Show error
        }
    // TODO::: rough in templates for this crap.
    }
    t.Execute(resp, data)
}

func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
    /* Show the state of the user's devices.
    */
    // get session info
    sessionInfo, err := self.getSessionInfo(req)
    if err != nil {
        http.Error(resp, err.Error(), 500)
        return
    }
    devInfo, err := self.store.GetDeviceInfo(sessionInfo.userId,
        sessionInfo.deviceId)
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

func (self *Handler) SendCmd(resp http.ResponseWriter, req *http.Request) {
    /* queue a command to a device
    */

    //TODO
    // is the user logged in?
        // no, they fail
    // validate the command and args
    // add to device's queue

}

func (self *Handler) StatusHandler(resp http.ResponseWriter, req *http.Request) {
    /* Show program status
    */
    resp.Write([]byte(fmt.Sprintf("%v", req.URL.Path[len("/status/"):])))
    resp.Write([]byte("OK"))
}

