/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"
)

type fakeWWS struct {
}

func Test_ClientBox_Add(t *testing.T) {
	c := NewClientBox()

	if err := c.Add("000", "000", &WWSs{}, 1); err != nil {
		t.Error("Failed on first add")
	}

	if err := c.Add("000", "001", &WWSs{}, 1); err == nil {
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
	cc, ok := c.Clients("000")
	if !ok {
		t.Errorf("Could not find 000 record")
	}
	if _, ok := cc["000"]; ok {
		t.Errorf("Record not removed")
	}
	c.Del("000", "001")
	if _, ok := c.Clients("000"); ok {
		t.Errorf("Record not purged")
	}
}

func fakeValidator(email, id string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		//resp.Header.Add("Content-Type", "application/json")
		email := "test+test@example.com"
		id := "0123456789abcdef"
		fmt.Fprintln(resp, fmt.Sprintf("{\"code\":200,\"idpClaims\":{\"fxa-generation\":1404770592087,\"fxa-lastAuthAt\":1404834090,\"fxa-verifiedEmail\":\"%s\",\"public-key\":{\"algorithm\":\"DS\",\"y\":\"\",\"p\":\"\",\"q\":\"\",\"g\":\"\"},\"principal\":{\"email\":\"%s@api.accounts.firefox.com\"},\"iat\":1404834172418,\"exp\":1404855782418,\"iss\":\"api.accounts.firefox.com\"}}", email, id))
	}))
}

func testHandler(config *util.MzConfig, t *testing.T) (*Handler, storage.Storage) {
	logger := &util.TestLog{T: t}
	metrics := &util.TestMetric{}
	storage, _ := storage.OpenInmemory(config, logger, metrics)

	return &Handler{config: config,
		logger:  logger,
		store:   storage,
		metrics: metrics,
	}, storage
}

func Test_Handler_verifyFxAAssertion(t *testing.T) {

	temail := "test+test@example.com"
	tid := "0123456789abcdef"

	ts := fakeValidator(temail, tid)
	defer ts.Close()

	config := util.NewMzConfig()
	config.Override("fxa.verifier", ts.URL)
	h, _ := testHandler(config, t)

	userid, email, err := h.verifyFxAAssertion("FakeAssertion")

	if userid != tid ||
		email != temail ||
		err != nil {
		t.Logf("Returned userid: %s, email: %s", userid, email)
		t.Errorf("Failed to validate mock assertion %s", err)
	}
}

func Test_Handler_clearSession(t *testing.T) {
	var ok bool

	config := util.NewMzConfig()
	h, _ := testHandler(config, t)
	sess := new(sessions.Session)
	sess.Values = make(map[interface{}]interface{})
	sess.Values[SESSION_USERID] = true
	sess.Values[SESSION_DEVICEID] = true
	sess.Values[SESSION_EMAIL] = true
	sess.Values[SESSION_TOKEN] = true
	sess.Values[SESSION_CSRFTOKEN] = true
	h.clearSession(sess)
	if _, ok = sess.Values[SESSION_USERID]; ok {
		t.Errorf("Userid not cleared")
	}
	if _, ok = sess.Values[SESSION_DEVICEID]; ok {
		t.Errorf("Deviceid not cleared")
	}
	if _, ok = sess.Values[SESSION_EMAIL]; ok {
		t.Errorf("Email not cleared")
	}
	if _, ok = sess.Values[SESSION_TOKEN]; ok {
		t.Errorf("Token not cleared")
	}
	if _, ok = sess.Values[SESSION_CSRFTOKEN]; ok {
		t.Errorf("CSRFToken not cleared")
	}
}

func Test_Handler_initData(t *testing.T) {
	tuid := "abcdef123456"
	config := util.NewMzConfig()
	config.Override("ws.hostname", "validhost")
	h, store := testHandler(config, t)
	store.RegisterDevice("TestUserID", &storage.Device{
		ID:   tuid,
		User: "TestUserID",
	})
	store.SetDeviceLocation(tuid, &storage.Position{})

	freq, _ := http.NewRequest("GET", "http://localhost/", nil)
	fresp := httptest.NewRecorder()
	fsess := &sessionInfoStruct{
		AccessToken: "testtest",
		CSRFToken:   "test-test",
	}

	// get no login data
	fsess.UserId = "TestUserID"
	fsess.Email = "Test@test.test"
	data, err := h.initData(fresp, freq, fsess)
	if err != nil {
		t.Errorf("initData: %s", err.Error())
	}
	if data == nil {
		t.Error("initData: No data returned")
		return
	}
	if data.Token == "" {
		t.Error("initData: invalid Token")
	}
	if host, ok := data.Host["Hostname"]; !ok || host != "validhost" {
		t.Error("initData: invalid hostname returned")
	}
	if len(data.DeviceList) == 0 {
		t.Error("initData: No devices returned for user")
	}
	// get login data
	freq, _ = http.NewRequest("GET", fmt.Sprintf("http://localhost/%s", tuid), nil)
	data, err = h.initData(fresp, freq, fsess)
	if err != nil {
		t.Errorf("initData: %s", err.Error())
	}
	// check the device list
	if data.Device.ID != tuid {
		t.Error("initData: incorrect device id")
	}
	if data.Device == nil {
		t.Error("initData:No specific device record returned")
		return
	}
	if data.Device.User != "TestUserID" {
		t.Error("initData: incorrect user id")
	}
}

// TODO: Finish tests for
// getUser - stub out session? (sigh, why do I have to keep doing this...)
// et al...
