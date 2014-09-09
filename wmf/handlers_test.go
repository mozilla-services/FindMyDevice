/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
    "testing"
    /*
    "net/http"
    "net/http/httptest"
    */
)

type fakeWWS struct {

}

func Test_ClientBox_Add(t *testing.T) {
    c := NewClientBox()

    if err := c.Add("000","000", &WWSs{}, 1); err != nil {
        t.Error("Failed on first add")
    }

    if err :=c.Add("000", "001", &WWSs{}, 1); err == nil {
        t.Error("Failed to limit instances")
    }
}

func Test_ClientBox_Del(t *testing.T) {
    c := NewClientBox()
    c.Add("000", "000", &WWSs{socket: &MockWSConn{}}, 0)
    c.Add("000", "001", &WWSs{socket: &MockWSConn{}}, 0)

    if f, err := c.Del("000", "000"); f == true || err != nil {
        t.Errorf("Could not delete id: %s, %s", err)
    }
    cc, ok := c.Clients("000");
    if !ok {
        t.Errorf("Could not find 000 record")
    }
    if _, ok := cc["000"]; ok {
        t.Errorf("Record not removed");
    }
    c.Del("000","001")
    if _, ok := c.Clients("000"); ok {
        t.Errorf("Record not purged");
    }
}

/*
func Test_Handler_verifyFxAAssertion(t *testing.T) {
    // TODO: create a draft assertion, stub out http to not call remotely
    ts := httptest.NewServer(http.HandlerFunc(func(resp http.Response, req *http.Request){
            resp.Header.Add("Content-Type", "application/json")
            fmt.Fprintln(resp, "
}
*/
