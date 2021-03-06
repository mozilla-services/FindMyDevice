/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"
)

func Test_ClientBox_Add(t *testing.T) {
	c := NewClientBox()
	c.Max = 1

	if err := c.Add("000", "000", &WWSs{}); err != nil {
		t.Error("Failed on first add")
	}

	if err := c.Add("000", "001", &WWSs{}); err == nil {
		t.Error("Failed to limit instances")
	}
}

func Test_ClientBox_Del(t *testing.T) {
	c := NewClientBox()
	c.Add("000", "000", &WWSs{socket: &MockWSConn{}})
	c.Add("000", "001", &WWSs{socket: &MockWSConn{}})

	if f, err := c.Del("000", "000"); f == true || err != nil {
		t.Errorf("Could not delete id: %s, %s", "000", err)
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

func fakeBadValidator(email, id string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		//resp.Header.Add("Content-Type", "application/json")
		email := "test+test@example.com"
		id := "0123456789abcdef"
		fmt.Fprintln(resp, fmt.Sprintf(`{"audience":"https://find.stage.mozaws.net","expires":2217367775002,"issuer":"api-accounts.stage.mozaws.net","email":"%s@api-accounts.stage.mozaws.net","idpClaims":{"fxa-generation":1428954416132,"fxa-lastAuthAt":1428967774,"fxa-verifiedEmail":"%s"},"status":"okay"}`, id, email))
	}))
}

func fakeValidator(email, id string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		//resp.Header.Add("Content-Type", "application/json")
		email := "test+test@example.com"
		id := "0123456789abcdef"
		fmt.Fprintln(resp, fmt.Sprintf(`{"audience":"https://find.stage.mozaws.net","expires":2217367775002,"issuer":"api.accounts.firefox.com","email":"%s@api.accounts.firefox.com","idpClaims":{"fxa-generation":1428954416132,"fxa-lastAuthAt":1428967774,"fxa-verifiedEmail":"%s"},"status":"okay"}`, id, email))
	}))
}

func testHandler(config *util.MzConfig, t *testing.T) (*Handler, storage.Storage) {
	logger := &util.TestLog{T: t}
	metrics := &util.TestMetric{}
	storage, _ := storage.OpenInmemory(config, logger, metrics)

	return &Handler{config: config,
		logger:       logger,
		store:        storage,
		metrics:      metrics,
		maxBodyBytes: 10485676,
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

func Test_Bad_Issuer(t *testing.T) {

	temail := "test+test@example.com"
	tid := "0123456789abcdef"

	ts := fakeBadValidator(temail, tid)
	defer ts.Close()

	config := util.NewMzConfig()
	config.Override("fxa.verifier", ts.URL)
	h, _ := testHandler(config, t)

	userid, email, err := h.verifyFxAAssertion("FakeAssertion")

	if err != ErrOAuth || "" != userid || "" != email {
		t.Logf("Returned userid: %s, email: %s", userid, email)
		t.Errorf("Failed to reject bad issuer")
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

func makeSession() {
	sessionStore = sessions.NewCookieStore([]byte("testtesttesttest"), []byte("testtesttesttest"))
	sessionStore.Options = &sessions.Options{
		Domain:   "box",
		Path:     "/",
		Secure:   false,
		HttpOnly: true,
	}
}

func fakeCookies(req *http.Request, email, userid, token, csrftoken string) error {
	var err error
	var session *sessions.Session
	resp := httptest.NewRecorder()
	session, err = sessionStore.Get(req, SESSION_NAME)
	if len(email) > 0 {
		session.Values[SESSION_EMAIL] = email
	}
	if len(userid) > 0 {
		session.Values[SESSION_USERID] = userid
	}
	if len(token) > 0 {
		session.Values[SESSION_TOKEN] = token
	}
	if len(csrftoken) > 0 {
		session.Values[SESSION_CSRFTOKEN] = csrftoken
	}

	if err = session.Save(req, resp); err != nil {
		return fmt.Errorf("Could not set cookie! %s", err.Error())
	}
	fcookies, ok := resp.HeaderMap["Set-Cookie"]
	if !ok {
		return fmt.Errorf("Cookie not set in header")
	}
	req.Header.Add("Cookie", strings.Split(fcookies[0], ";")[0])
	return nil
}

func Test_Handler_getUser(t *testing.T) {
	var err error

	var name = "Test_Handler_getUser"
	var email = "test@test.co"
	var uid = "123456abcdef"

	makeSession()

	fresp := httptest.NewRecorder()

	h, _ := testHandler(util.NewMzConfig(), t)

	freq, err := http.NewRequest("GET", "http://box/", nil)
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}
	err = fakeCookies(freq, email, uid, "", "")
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}

	tuid, temail, err := h.getUser(fresp, freq)

	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}
	if tuid != uid {
		t.Errorf("%s: uid mismatch", name)
	}
	if temail != email {
		t.Errorf("%s: email mismatch", email)
	}
	// check the headers
	headers := fresp.Header()
	hv := map[string]string{
		"X-Frame-Options":        "deny",
		"X-Xss-Protection":       "1; mode=block",
		"X-Content-Type-Options": "nosniff",
		//	"X-Content-Security-Policy": "default-src 'self'",
		//	"Content-Security-Policy":   "default-src 'self'",
		//	"X-Webkit-Csp":              "default-src 'self'",
		"Frame-Options": "deny",
	}
	for k, v := range hv {
		if j := headers.Get(k); j != v {
			t.Errorf("Invalid header %s != %s (%s)", k, v, j)
		}
	}
	// TODO: Test w/ fake assertion (or use Test_Handler_Verify)
}

func Test_Handler_getSessionInfo(t *testing.T) {

	var err error
	var name = "Test_Handler_getSessionInfo"
	var email = "test@test.co"
	var uid = "abcdef123456"
	var devid = "123456abcdef"
	var token = "123abc"
	var csrftoken = "abcd1234"

	makeSession()
	h, _ := testHandler(util.NewMzConfig(), t)
	freq, _ := http.NewRequest("GET", "http://box/"+devid, nil)
	err = fakeCookies(freq, email, uid, token, csrftoken)
	if err != nil {
		t.Errorf("%s:%s", name, err.Error())
	}
	session, _ := sessionStore.Get(freq, SESSION_NAME)
	info, err := h.getSessionInfo(nil, freq, session)
	if info.UserId != uid ||
		info.DeviceId != devid ||
		info.Email != email ||
		info.AccessToken != token ||
		info.CSRFToken != csrftoken {
		t.Errorf("%#v: returned session info contained invalid data", info)
	}
}

func Test_Handler_Cmd(t *testing.T) {
	var name = "Test_Handler_Cmd"
	var email = "test@test.co"
	var uid = "abcdef123456"
	var token = "123abc"
	var csrftoken = "abcd1234"
	var lat = 123.45678
	var lon = 12.34567
	var ti = time.Now().UTC().Unix()

	makeSession()
	config := util.NewMzConfig()
	config.Override("auth.disabled", "true")
	config.Override("hawk.disabled", "true")
	config.Override("auth.force_user", fmt.Sprintf("%s %s", uid, email))
	h, store := testHandler(config, t)
	devId, err := store.RegisterDevice(uid, &storage.Device{Name: "test", User: uid})
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}
	// create a fake tracking record.
	track, _ := json.Marshal(struct {
		T interface{} `json:"t"`
	}{struct {
		Ok bool    `json:"ok"`
		La float64 `json:"la"`
		Lo float64 `json:"lo"`
		Ti int64   `json:"ti"`
		Ac float64 `json:"acc"`
		Ha bool    `json:"has_passcode"`
	}{true, lat, lon, ti, 100, true}})
	freq, _ := http.NewRequest("POST", "http://box/"+devId, bytes.NewBuffer(track))
	fakeCookies(freq, email, uid, token, csrftoken)
	fresp := httptest.NewRecorder()
	// create the fake client
	mConn := &MockWSConn{}
	Clients.Add(devId, "0000", &WWSs{socket: mConn})
	store.StoreCommand(devId, "{}", "")

	// and finally make the test call...
	h.Cmd(fresp, freq)
	// This is the last command we pushed.
	if fresp.Body.String() != "{}" {
		t.Errorf("%s: returned command did not match expectations. %s", name, fresp.Body.String())
	}

	//TODO test other commands as well.
}

func Test_Handler_Queue(t *testing.T) {
	var name = "Test_Handler_Queue"
	var uid = "abcdef123456"
	var devid = "123456abcdef"

	makeSession()
	config := util.NewMzConfig()
	// don't try to send out the push command
	config.Override("push.disabled", "true")
	h, store := testHandler(config, t)
	dev := &storage.Device{Name: "test", ID: devid, User: uid, Accepts: "trle"}
	rargs := &replyType{"d": 60}
	rep := make(replyType)

	status, err := h.Queue(dev, "t", rargs, &rep)
	if status != 200 || err != nil {
		t.Errorf("Command Queue failed with status %d: %s", status, err)
	}
	cmd, ctype, err := store.GetPending(devid)
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}
	if cmd != "{\"t\":{\"d\":60}}" || ctype != "t" {
		t.Errorf("%s: Incorrect command returned %s , %s", name, cmd, ctype)
	}
	// Add additional Queue commands
}

func Test_Handler_RestQueue(t *testing.T) {
	var name = "Test_Handler_RestQueue"
	var email = "test@test.co"
	var uid = "abcdef123456"
	var token = "123abc"
	var csrftoken = "abcd1234"

	makeSession()
	config := util.NewMzConfig()
	config.Override("auth.disabled", "true")
	config.Override("hawk.disabled", "true")
	config.Override("push.disabled", "true")
	config.Override("auth.force_user", fmt.Sprintf("%s %s", uid, email))
	h, store := testHandler(config, t)
	devId, err := store.RegisterDevice(uid, &storage.Device{Name: "test", User: uid, Accepts: "trle"})
	if err != nil {
		t.Errorf("%s: %s", name, err.Error())
	}
	// create a fake tracking record.
	track, _ := json.Marshal(struct {
		T interface{} `json:"t"`
	}{struct {
		D int64 `json:"d"`
	}{60}})
	freq, _ := http.NewRequest("POST", "http://box/"+devId, bytes.NewBuffer(track))
	freq.Header.Add("X-CSRFTOKEN", csrftoken)
	fakeCookies(freq, email, uid, token, csrftoken)
	fresp := httptest.NewRecorder()
	// create the fake client
	mConn := &MockWSConn{}
	Clients.Add(devId, "0000", &WWSs{socket: mConn})
	h.RestQueue(fresp, freq)
	if fresp.Code != 200 {
		t.Errorf("%s: failed to return success", name)
	}
	cmd, ctype, err := store.GetPending(devId)
	if cmd != "{\"t\":{\"d\":60}}" || ctype != "t" {
		t.Errorf("%s: Incorrect command returned %s , %s", name, cmd, ctype)
	}

	// TODO: add additional cmds
}

func Test_Handler_checkToken(t *testing.T) {
	var name = "Test_Handler_Test_Handler_checkToken"
	var devId = "0000"
	var uid = "1111"
	var csrftoken = "abcdef123456"
	var token = ""
	var email = ""

	makeSession()
	config := util.NewMzConfig()
	freq, _ := http.NewRequest("POST", "http://box/"+devId, nil)
	h, _ := testHandler(config, t)
	session, _ := sessionStore.Get(freq, SESSION_NAME)
	if h.checkToken(session, freq) {
		t.Errorf("%s: Failed to reject tokenless request", name)
	}
	freq.Header.Add("X-CSRFTOKEN", csrftoken)
	fakeCookies(freq, email, uid, token, csrftoken)
	session, _ = sessionStore.Get(freq, SESSION_NAME)
	if !h.checkToken(session, freq) {
		t.Errorf("%s: Failed to accept tokened request", name)
	}

	freq, _ = http.NewRequest("POST", "http://box/"+devId, nil)
	freq.Header.Add("X-CSRFTOKEN", "invalid")
	fakeCookies(freq, email, uid, token, csrftoken)
	session, _ = sessionStore.Get(freq, SESSION_NAME)
	if h.checkToken(session, freq) {
		t.Errorf("%s: Failed to reject invalid token", name)
	}
}

func Test_Handler_UserDevices(t *testing.T) {
	var name = "Test_Handler_Test_Handler_UserDevices"
	var devid = "1234"
	var uid = "1111"
	var email = "test@test"
	var token = "0000"
	var csrftoken = "0000"

	makeSession()
	config := util.NewMzConfig()
	h, store := testHandler(config, t)
	_ = store

	freq, _ := http.NewRequest("GET", "http://box/devices", nil)
	fresp := httptest.NewRecorder()
	h.UserDevices(fresp, freq)
	if fresp.Code != 401 {
		t.Errorf("%s: Did not block access for unauthorized user", name)
	}
	fresp = httptest.NewRecorder()
	fakeCookies(freq, email, uid, token, csrftoken)
	h.UserDevices(fresp, freq)
	if fresp.Code != 204 {
		t.Errorf("%s: Did not return 204 for no devices registered", name)
	}
	store.RegisterDevice(uid, &storage.Device{
		ID:   devid,
		User: uid,
		Name: "Test",
	})
	fresp = httptest.NewRecorder()
	h.UserDevices(fresp, freq)
	t.Logf("%s: %+v  %+v", name, freq, fresp)
	if fresp.Code != 200 {
		t.Errorf("%d: Incorrect status returned", fresp.Code)
	}
	ret := make(map[string]interface{})
	err := json.Unmarshal(fresp.Body.Bytes(), &ret)
	if err != nil {
		t.Errorf("%s: Invalid JSON returned %s", name, err.Error())
	}
	item := ret["devices"].([]interface{})[0].(map[string]interface{})
	if _, ok := item["URL"]; !ok || item["ID"].(string) != devid {
		t.Errorf("%s: Incorrect return", name)
	}
}

func Test_getLocLang(t *testing.T) {
	config := util.NewMzConfig()
	h, _ := testHandler(config, t)

	req, _ := http.NewRequest("GET", "http://localhost/1/l10n/client.json", nil)
	req.Header.Add("Accept-Language", "es,fo,en-us;q=0.7,en;q=0.3")

	result := h.getLocLang(req)
	t.Logf("results: %+v\n", result)
	if len(result) == 0 {
		t.Errorf("getLocLang failed to return any results")
	}
	if len(result) != 6 {
		t.Errorf("getLocLang returned too few results")
	}
	if result[0].Lang != "es" {
		t.Errorf("getLocLang failed to sort languages correctly: %s", result[0].Lang)
	}
	if result[2].Lang != "en_US" {
		t.Errorf("getLocLang failed normalization to lower_UPPER")
	}
	if result[5].Lang != "en" {
		t.Errorf("getLocLang failed to include 'en'")
	}

	req, _ = http.NewRequest("GET", "http://localhost/1/l10n/client.json", nil)
	req.Header.Add("Accept-Language", "{:;}() echo invalid!")
	result = h.getLocLang(req)
	t.Logf("results: %+v\n", result)
	if result[0].Lang != "en" {
		t.Errorf("getLocLang failed to gracefully handle invalid Accept-Language")
	}
}

func Test_LangPath(t *testing.T) {
	tmpDir := os.TempDir()
	testTemplate := "{{.Root}}/{{.Lang}}_test.txt"
	testTmpl, _ := template.New("test").Parse(testTemplate)
	testText := "{\"foo\": \"bar\", \"gorp\":\"\"}"
	tf_name := filepath.Join(tmpDir, "en_test.txt")
	tf, err := os.Create(tf_name)
	if err != nil {
		t.Fatalf("could not gen test file %s", err.Error())
	}
	defer os.Remove(tf_name)
	tf.Write([]byte(testText))
	tf.Close()

	// this runs .path & .Check
	lp, err := NewLangPath(testTmpl, tmpDir, "EN")
	if err != nil {
		t.Fatalf("Could not get LangPath: %s", err.Error())
	}
	buff := new(bytes.Buffer)
	if err = lp.Write("en", buff); err != nil {
		t.Fatalf("Could not write buffer: %s", err.Error())
	}
	if buff.String() != testText {
		t.Fatalf("Data did not match: %s != %s", buff.String(), testText)
	}
	if err = lp.Load("en"); err != nil {
		t.Fatalf("Could not load test data: %s", err.Error())
	}
	if lp.Localize("foo") != "bar" {
		t.Fatalf("Incorrect valid value returned")
	}
	if lp.Localize("bar") != "bar" {
		t.Fatalf("Incorrect invalid value returned")
	}
	if lp.Localize("gorp") != "gorp" {
		t.Fatalf("Blank string did not return delocalized value")
	}
	// Obviously, this should return an error, not the data.
	lp, err = NewLangPath(testTmpl, tmpDir, "/etc/hostname")
	if err != ErrNoLanguage {
		t.Fatalf("Incorrect error returned")
	}

}

func Test_Signin(t *testing.T) {
	config := util.NewMzConfig()
	h, _ := testHandler(config, t)
	result := map[string]string{
		"http://localhost/signin/":               "signin",
		"http://localhost/signin/?action=signup": "signup",
		"http://localhost/signin/?action=banana": "signin",
	}

	for sign_url, action := range result {

		req, _ := http.NewRequest("GET", sign_url, nil)
		fresp := httptest.NewRecorder()
		h.Signin(fresp, req)
		if fresp.Code != 302 {
			t.Error("Signin response not a 302")
		}
		redir, err := url.Parse(fresp.Header().Get("Location"))
		if err != nil {
			t.Errorf("Returned Location URL is unparsable: %s", err)
		}
		if redir.Query().Get("action") != action {
			t.Error("Returned URL for %s did not specify action as '%s'",
				sign_url, action)
		}
	}
}

// TODO: Finish tests for
// getUser - stub out session? (sigh, why do I have to keep doing this...)

func Test_Static(t *testing.T) {
	config := util.NewMzConfig()
	h, _ := testHandler(config, t)
	fresp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "../../../../../etc/passwd", nil)
	h.Static(fresp, req)
	if fresp.Body.Len() > 0 {
		t.Error("Static failed to return blank password file")
	}
}

// et al...
