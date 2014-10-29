/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"text/template"

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

func testServer(email, id string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		//resp.Header.Add("Content-Type", "application/json")
		email := "test+test@example.com"
		id := "0123456789abcdef"
		fmt.Fprintln(resp, fmt.Sprintf("{\"code\":200,\"idpClaims\":{\"fxa-generation\":1404770592087,\"fxa-lastAuthAt\":1404834090,\"fxa-verifiedEmail\":\"%s\",\"public-key\":{\"algorithm\":\"DS\",\"y\":\"\",\"p\":\"\",\"q\":\"\",\"g\":\"\"},\"principal\":{\"email\":\"%s@api.accounts.firefox.com\"},\"iat\":1404834172418,\"exp\":1404855782418,\"iss\":\"api.accounts.firefox.com\"}}", email, id))
	}))
}

func testHandler(config *util.MzConfig, t *testing.T) *Handler {
	logger := &util.TestLog{T: t}
	metrics := &util.TestMetric{}
	storage, _ := storage.OpenInmemory(config, logger, metrics)

	return &Handler{config: config,
		logger:  logger,
		store:   storage,
		metrics: metrics,
	}
}

func Test_Handler_verifyFxAAssertion(t *testing.T) {

	temail := "test+test@example.com"
	tid := "0123456789abcdef"

	ts := testServer(temail, tid)
	defer ts.Close()

	config := util.NewMzConfig()
	config.Override("fxa.verifier", ts.URL)
	h := testHandler(config, t)

	userid, email, err := h.verifyFxAAssertion("FakeAssertion")

	if userid != tid ||
		email != temail ||
		err != nil {
		t.Logf("Returned userid: %s, email: %s", userid, email)
		t.Errorf("Failed to validate mock assertion %s", err)
	}
}

func Test_getLocLang(t *testing.T) {
	config := util.NewMzConfig()
	h := testHandler(config, t)

	req, _ := http.NewRequest("GET", "http://localhost/1/l10n/client.json", nil)
	req.Header.Add("Accept-Language", "foo-BA;q=0.8,bar-GO;q=0.9")

	result := h.getLocLang(req)
	t.Logf("results: %+v\n", result)
	if len(result) == 0 {
		t.Errorf("getLocLang failed to return any results")
	}
	if len(result) != 5 {
		t.Errorf("getLocLang returned too few results")
	}
	if result[0].Lang != "bar_GO" {
		t.Errorf("getLocLang failed to sort languages correctly: %s", result[0].Lang)
	}
	if result[4].Lang != "en" {
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
	testText := "{\"foo\": \"bar\"}"
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
		t.Fatalf("Could not get LangPath: %s", err.Error)
	}
	buff := new(bytes.Buffer)
	if err = lp.Write("en", buff); err != nil {
		t.Fatalf("Could not write buffer: %s", err.Error)
	}
	if buff.String() != testText {
		t.Fatalf("Data did not match: %s != %s", buff.String(), testText)
	}
	if err = lp.Load("en"); err != nil {
		t.Fatalf("Could not load test data: %s", err.Error())
	}
	if lp.Get("foo") != "bar" {
		t.Fatalf("Incorrect valid value returned")
	}
	if lp.Get("bar") != "bar" {
		t.Fatalf("Incorrect invalid value returned")
	}
	// Obviously, this should return an error, not the data.
	lp, err = NewLangPath(testTmpl, tmpDir, "/etc/hostname")
	if err != ErrNoLanguage {
		t.Fatalf("Incorrect error returned")
	}

}

// TODO: Finish tests for
// getUser - stub out session? (sigh, why do I have to keep doing this...)
// et al...
