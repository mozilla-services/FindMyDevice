package wmf

import (
    "mozilla.org/util"
    "mozilla.org/wmf/storage"

    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"

)

type Handler struct {
    config util.JsMap
    logger *util.HekaLogger
    store  *storage.Storage
}

func NewHandler (config util.JsMap, logger *util.HekaLogger, store *storage.Storage) * Handler {
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
    var pushurl string
    var deviceid string
    var secret string
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
        if assert, ok := buffer["assertion"]; !ok {
            self.logger.Error("handler", "Missing assertion", nil)
            http.Error(resp, "Unauthorized", 401)
            return
        } else {
            // userid = verifyAssertion(assertion, domain)
        }

        if pushUrl, ok = buffer["pushurl"]; !ok {
            self.logger.Error("handler", "Missing SimplePush url", nil)
            http.Error(resp, "Bad Data", 400)
            return
        }
        if secret, ok = buffer["secret"]; !ok {
            self.logger.Error("handler", "Missing HAWK secret", nil)
            http.Error(resp, "Bad Data", 400)
            return
        }
        if deviceid, ok = buffer["deviceid"]; !ok {
            deviceid, err = util.GenUUID4()
        }
        // create the new device record
        err = storage.RegisterDevice(userid, deviceid, pushurl, secret)
        if err != nil {
            self.logger.Error("handler", "Error storing data", nil)
            http.Error(resp, "Server error", 500);
            return
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

}

func (self *Handler) State(resp http.ResponseWriter, req *http.Request) {
    /* Show the state of the user's devices.
    */
}

func (self *Handler) StatusHandler(resp http.ResponseWriter, req *http.Request) {
    /* Show program status
    */
    resp.Write([]byte("OK"))
}
