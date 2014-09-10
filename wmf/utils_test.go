/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"testing"
)

func Test_digitsOnly(t *testing.T) {
	if digitsOnly('0') != '0' {
		t.Errorf("Failed to recognize digit")
	}
	if digitsOnly('a') != -1 {
		t.Errorf("Failed to discard non-digit")
	}
}

func Test_asciiOnly(t *testing.T) {
	if asciiOnly(' ') != ' ' {
		t.Error("Failed to recognize ASCII")
	}
	if asciiOnly('\a') != -1 {
		t.Error("Failed to discard control character")
	}
	if asciiOnly('☃') != -1 {
		t.Error("Failed to discard UTF8 extended character")
	}
}

func Test_deviceIdFilter(t *testing.T) {
	if deviceIdFilter('A') != 'A' {
		t.Error("Failed to accept valid DeviceID character")
	}
	if deviceIdFilter('+') != rune(-1) {
		t.Error("Failed to reject invalid DeviceID character")
	}
}

func Test_assertionFilter(t *testing.T) {
	if deviceIdFilter('A') != 'A' {
		t.Error("Failed to accept valid Assertion character")
	}
	if deviceIdFilter('+') != rune(-1) {
		t.Error("Failed to reject invalid Assertion character")
	}
}

func Test_parseBody(t *testing.T) {
	t_good := struct {
		Foo int64 `json:"foo"`
	}{123}
	ts, _ := json.Marshal(t_good)
	tr := ioutil.NopCloser(bytes.NewBuffer(ts))

	reply, body, err := parseBody(tr)
	if reply["foo"].(float64) != 123 {
		t.Error("foo not found or invalid")
	}
	if body != string(ts) {
		t.Error("body does not match expected string")
	}
	t_bad := ioutil.NopCloser(bytes.NewBuffer([]byte("{\"InvalidJson\",}")))
	reply, body, err = parseBody(t_bad)
	if err == nil {
		t.Error("Failed to catch bad JSON")
	}
}

func Test_isTrue(t *testing.T) {
	if !isTrue("true") {
		t.Error("\"True\" not true")
	}
	if !isTrue(1) {
		t.Error("1 not true")
	}
	if !isTrue(true) {
		t.Error("true not true")
	}
	if isTrue("Banana") {
		t.Error("\"Banana\" is true")
	}
	if isTrue("  False") {
		t.Error("\"  False\" is true")
	}
}

func Test_minInt(t *testing.T) {
	if minInt(10, 100) != 10 {
		t.Error("minInt returned wrong value")
	}
}

func Test_getDevFromUrl(t *testing.T) {
	var r string
	u, _ := url.Parse("http://")
	if r = getDevFromUrl(u); r != "" {
		t.Error("Bad parse of short url.")
	}
	u, _ = url.Parse("http://box/0123456789abcdef/")
	if r = getDevFromUrl(u); r != "0123456789abcdef" {
		t.Error("Failed to find slashed deviceid. %s", r)
	}
	u, _ = url.Parse("http://box/0123456789abcdef")
	if r = getDevFromUrl(u); r != "0123456789abcdef" {
		t.Error("Failed to find deviceid. %s", r)
	}
	u, _ = url.Parse("http://box/1234567890123456789012345678901234567890")
	if r = getDevFromUrl(u); r != "12345678901234567890123456789012" {
		t.Error("Failed to truncate to 32 characters:%s", r)
	}
	u, _ = url.Parse("http://box/DeadBeefWRONG")
	if r = getDevFromUrl(u); r != "DeadBeef" {
		t.Error("Failed to trim bad characters:%s", r)
	}
}
