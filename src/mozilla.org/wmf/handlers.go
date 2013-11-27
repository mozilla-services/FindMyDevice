package wmf

import (
    "mozilla.org/util"
    "mozilla.org/wmf/storage"

    "encoding/json"
    "io/ioutil"
    "net/http"
    "strconv"
    "fmt"

)

type Handler struct {
    config util.JsMap
    logger *util.HekaLogger
    store  *storage.Storage
}

func NewHandler (config util.JsMap, logger *util.HekaLogger, store *storage.Storage) *Handler {
    return &Handler{ config: config,
        logger: logger,
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
    }
    }
    return

}

func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
    /* Pass the latest command off to the device.
    */
    var body [1024]byte
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
        reply := make(map[string]interface{})
        merr := json.Unmarshal(body, reply)
        // handle command acks
        for cmd, args := range reply {
            switch cmd {
            case "l":
                // locked?
            case "r":
                // ring
            case "m":
                // message
            case "e":
                // erase
            case "t":
                // track
                // store tracking info.
        }
    }

    // reply with pending commands
    // 
    cmd, err := json.Marshall(self.store.GetPending(deviceId))
    if err == nil {
        resp.Write(cmd)
    } else {
        self.logger.Error(logCat, "Could not send commands", util.Fields{"error":err}) 
    }
    resp.Write([]byte("{}"))

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
