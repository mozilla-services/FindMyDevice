/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

// TODO: Finish tests for
// getUser - stub out session? (sigh, why do I have to keep doing this...)
// et al...
