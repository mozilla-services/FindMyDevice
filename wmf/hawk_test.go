/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package wmf

import (
	"github.com/mozilla-services/FindMyDevice/util"
	"net/http"
	"regexp"
	"testing"
)

var fake_hawk = &Hawk{
	Hash:      "hash",
	Signature: "signature",
	Nonce:     "nonce",
	Time:      "time",
	Path:      "path",
	Port:      "port",
}

func Test_GenNonce(t *testing.T) {
	// input is 10 bits of random, base64 encoded and padded.
	if len(GenNonce(0)) != 8 {
		t.Errorf("Nonce too short")
	}
	if len(GenNonce(10)) != 16 {
		t.Errorf("Nonce not long enough")
	}
	if GenNonce(0) == GenNonce(0) {
		t.Errorf("Nonce not unique")
	}
}

func Test_Nonces(t *testing.T) {
	nonce := GenNonce(0)

	if !HawkNonces.Add(nonce) {
		t.Errorf("Could not add nonce to HawkNonces")
	}
	if HawkNonces.Add(nonce) {
		t.Errorf("Duplicate Nonce not blocked")
	}
}

func Test_Clear(t *testing.T) {
	h := fake_hawk

	h.Clear()
	if h.Hash != "" ||
		h.Signature != "" ||
		h.Nonce != "" ||
		h.Time != "" ||
		h.Path != "" ||
		h.Port != "" {
		t.Errorf("Did not clear HAWK object sufficiently: %+v", h)
	}
}

func Test_AsHeader(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box/0123456789abcdef", nil)

	fh := fake_hawk
	fh.Signature = ""
	head := fh.AsHeader(fr, "0123456789", "body", "extra", "secret")
	if m, _ := regexp.Match("Hawk id=\"0123456789\", ts=\"\\d+\", nonce=\".{8}\", ext=\"extra\", hash=\"[a-zA-Z0-9=]+\", mac=\"[a-zA-Z0-9\\+/=]+\"", []byte(head)); !m {
		t.Errorf("Invalid header returned: %s", head)
	}
}

func Test_getFullPath(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box/0123?foo=bar#gorp", nil)

	if p := getFullPath(fr); p != "/0123?foo=bar#gorp" {
		t.Errorf("Could not get full path from request (%s)", p)
	}
}

func Test_getHostPort(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box:000/0123?foo=:123#gorp", nil)

	hh := &Hawk{}

	if h, p := hh.getHostPort(fr); h != "box" || p != "000" {
		t.Errorf("Could not parse host (%s) or port (%s)", h, p)
	}
}

func Test_genHash(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box/0123", nil)

	hh := &Hawk{}

	if h := hh.genHash(fr, "this is a test"); h != "mKGKmU7JHwdwUV7rEKgkA0FQnlIucVWWqdVaQVLOjn8=" {
		t.Errorf("Invalid hash generated (%s)", h)
	}
}

func Test_GenerateSignature(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box/0123", nil)

	hh := &Hawk{}

	if err := hh.GenerateSignature(fr, "extra", "body", "secret"); err != nil {
		t.Errorf("GenerateSignature returned error %s", err.Error())
	}
	if hh.Path != "/0123" {
		t.Errorf("Invalid Path stored (%s)", hh.Path)
	}
	if hh.Host != "box" {
		t.Errorf("Invalid Host stored (%s)", hh.Host)
	}
	if hh.Extra != "extra" {
		t.Errorf("Invalid Extra Stored (%s)", hh.Extra)
	}

	hh.Clear()
	hh.Time = "000"
	hh.Nonce = "000"
	hh.Method = "POST"
	hh.Hash = "000"
	hh.Path = "000"
	if err := hh.GenerateSignature(fr, "000", "body", "secret"); err != nil {
		t.Errorf("GenerateSignture returned an error %s", err.Error())
	}
	if hh.Signature != "EHytGbwULFs9bYFurnTwGc0k+ZSsVEtCuoGDxs3iV20=" {
		t.Errorf("Invalid signature %s", hh.Signature)
	}
}

func Test_ParseAuthHeader(t *testing.T) {
	fr, _ := http.NewRequest("GET", "http://box/0123", nil)

	hh := &Hawk{config: &util.MzConfig{}}

	fr.Header.Add("Authorization", "Hawk id=\"0123456789\", ts=\"1410285986\", nonce=\"CAhQGkr7\", ext=\"extra\", hash=\"elvaRjdhz7QeKO4WtsxibZwGEaTtRqVNRYwx5yx074w=\", mac=\"nqKnXZ12mluJj5gGuYqN9OzDCkAxw9lUxoOFDG0wQVI=\"")
	if err := hh.ParseAuthHeader(fr, nil); err != nil {
		t.Errorf("ParseAuthHeader returned an error %s", err.Error())
	}
	if hh.Id != "0123456789" ||
		hh.Time != "1410285986" ||
		hh.Nonce != "CAhQGkr7" ||
		hh.Method != "GET" ||
		hh.Path != "/0123" ||
		hh.Host != "box" ||
		hh.Hash != "elvaRjdhz7QeKO4WtsxibZwGEaTtRqVNRYwx5yx074w=" ||
		hh.Signature != "nqKnXZ12mluJj5gGuYqN9OzDCkAxw9lUxoOFDG0wQVI=" {
		t.Errorf("ParseAuthHeader incorrectly parsed header %+v", hh)
	}

	if err := hh.ParseAuthHeader(fr, nil); err == nil {
		t.Errorf("ParseAuthHeader failed to detect replay")
	}
}

func Test_Compare(t *testing.T) {
	fh := &Hawk{Signature: "123==="}

	if !fh.Compare("123") {
		t.Errorf("Failed to properly equate signatures")
	}
}
