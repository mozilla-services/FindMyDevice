package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"mozilla.org/util"

	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

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

// There's no built in min function.
// awesome.
func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// get the device id from the URL path
func getDevFromUrl(u *url.URL) (devId string) {
	if !strings.Contains(u.Path, "/") {
		return ""
	}
	elements := strings.Split(u.Path, "/")
    devId = strings.Map(deviceIdFilter, elements[len(elements)-1])
    if len(devId) > 32 {
        devId = devId[:32]
    }
    return devId
}

// get the user id info from the session. (userid/devid)
func setSessionInfo(resp http.ResponseWriter, session *sessionInfo) (err error) {
	if session != nil {
		cookie := http.Cookie{Name: "user",
			Value: session.UserId,
			Path:  "/"}
		http.SetCookie(resp, &cookie)
	}
	return err
}
