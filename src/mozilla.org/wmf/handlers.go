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

func (self *Handler) decodeData(body []byte) (reply map[string]interface{}, err error) {
    return
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

    if body, err := ioutil.ReadAll(req.Body); err != nil {
        http.Error(resp, "No body", http.StatusBadRequest)
    } else {
        err := json.Unmarshal(body, &buffer)
        if err != nil {
            self.logger.Error("handler", "Unparsable data",
                util.Fields{"raw": string(body), "error":err.Error()})
            http.Error(resp, "Bad Data", 400)
            return
        }
        if _, ok := buffer["assertion"]; !ok {
            self.logger.Error("handler", "Missing assertion", nil)
            http.Error(resp, "Unauthorized", 401)
            return
        } else {
            // assert := buffer["assertion"].string()
            // userid = verifyAssertion(assertion, domain)
        }

        if _, ok = buffer["pushurl"]; !ok {
            self.logger.Error("handler", "Missing SimplePush url", nil)
            http.Error(resp, "Bad Data", 400)
            return
        } else {
            pushUrl = buffer["pushurl"].(string)
        }
        if _, ok = buffer["secret"]; !ok {
            self.logger.Error("handler", "Missing HAWK secret", nil)
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
            self.logger.Error("handler", "Error storing data", nil)
            http.Error(resp, "Server error", 500)
            return
        } else {
        if devId != deviceid {
            self.logger.Error("handler", "Different deviceID returned",
                util.Fields{"original": deviceid, "new": devId})
            http.Error(resp, "Server error", 500)
            return
        }
    }
    }
    return

}

func (self *Handler) Login(resp http.ResponseWriter, req *http.Request) {
    /* Handle a user login to the web UI
    */

}

func (self *Handler) Cmd(resp http.ResponseWriter, req *http.Request) {
    /* Pass the latest command off to the device.
    */
    // get the record for the deviceID
    deviceId := strings.Split(req.URL.Path,"/")[1]
    //decode the body
    var body [1024]byte
    var err error
    var l int
    
    l, err = req.Body.Read(body)
    if l > 0 {
        reply := make(map[string]interface{})
        merr := json.Unmarshal(body, reply)
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
        }
    }
    
    resp.Write([]byte("OK"))
    

}

func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
    /* Show the state of the user's devices.
    */
}

func (self *Handler) StatusHandler(resp http.ResponseWriter, req *http.Request) {
    /* Show program status
    */
    resp.Write([]byte(fmt.Sprintf("%v", req.URL.Path[len("/status/"):])))
    resp.Write([]byte("OK"))
}
