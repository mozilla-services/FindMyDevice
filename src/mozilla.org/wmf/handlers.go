package wmf

import (
    "mozilla.org/util"
    "mozilla.org/wmf/storage"

    "errors"
    "encoding/json"
    "io/ioutil"
    "net/http"
    "strconv"
    "strings"
    "fmt"

)

type Handler struct {
    config util.JsMap
    logger *util.HekaLogger
    store  *storage.Storage
    devId string
}

var InvalidReplyErr = errors.New("Invalid Command Response")

func NewHandler (config util.JsMap, logger *util.HekaLogger, store *storage.Storage) *Handler {
    return &Handler{ config: config,
        logger: logger,
        store: store}
}

type reply_t map[string]interface{}

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

    logCat := "handler:Register"

    if body, err := ioutil.ReadAll(req.Body); err != nil {
        http.Error(resp, "No body", http.StatusBadRequest)
    } else {
        err := json.Unmarshal(body, &buffer)
        if err != nil {
            self.logger.Error(logCat, "Unparsable data",
                util.Fields{"raw": string(body), "error":err.Error()})
            http.Error(resp, "Bad Data", 400)
            return
        }
        if _, ok := buffer["assertion"]; !ok {
            self.logger.Error(logCat, "Missing assertion", nil)
            http.Error(resp, "Unauthorized", 401)
            return
        } else {
            // assert := buffer["assertion"].string()
            // userid = verifyAssertion(assertion, domain)
        }

        if _, ok = buffer["pushurl"]; !ok {
            self.logger.Error(logCat, "Missing SimplePush url", nil)
            http.Error(resp, "Bad Data", 400)
            return
        } else {
            pushUrl = buffer["pushurl"].(string)
        }
        if _, ok = buffer["secret"]; !ok {
            self.logger.Error(logCat, "Missing HAWK secret", nil)
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
            self.logger.Error(logCat, "Error storing data", nil)
            http.Error(resp, "Server error", 500)
            return
        } else {
            if devId != deviceid {
                self.logger.Error(logCat, "Different deviceID returned",
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

    logCat := "handler:Cmd"
    // get the record for the deviceID
    deviceId := strings.Split(req.URL.Path,"/")[1]
    if deviceId == "" {
        self.logger.Error(logCat, "Invalid call (No device id)", nil)
        http.Error(resp, "Unauthorized", 401)
        return
    }
    if self.store.ValidateDevice(deviceId) == false {
        self.logger.Error(logCat, "Cmd:Unknown device requesting cmd", util.Fields{
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
            self.logger.Error(logCat, "Could not unmarshal data", util.Fields{
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
                self.logger.Error(logCat, "Error handling command",
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
            self.logger.Error(logCat, "Error marshalling pending cmd",
                util.Fields{"error": err.Error(),
                            "device": deviceId})
            http.Error(resp, "Server Error", http.StatusServiceUnavailable)
            return
        }
        resp.Write(jcmd)
    } else {
        self.logger.Error(logCat, "Could not send commands", util.Fields{"error":err.Error()})
        http.Error(resp, "Server Error", http.StatusServiceUnavailable)
    }
    resp.Write([]byte("{}"))

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

// user login functions

func (self *Handler) Login(resp http.ResponseWriter, req *http.Request) {
    /* Handle a user login to the web UI
    */
    // validate the assertion
    // get/create the userid
    // create the user record (if not already present)
    // send the device update request.
    // show the map/command page.

}

func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
    /* Show the state of the user's devices.
    */
    // get session info
}

func (self *Handler) SendCmd(resp http.ResponseWriter, req *http.Request) {
    /* queue a command to a device
    */
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
