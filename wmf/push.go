package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"
	"net/http"
)

func SendPush(devRec *storage.Device, config *util.MzConfig) error {
	// wow, so very tempted to make sure this matches the known push server.
	bbody := []byte{}
	body := bytes.NewReader(bbody)
	/* If your server is not trustfully signed, the following will fail.
	   If partners are unable/unwilling to trustfully sign servers,
	   it is possible to skip validation by using
	    &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	   however that is not advised as a general policy for damn good reasons.

	*/
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
		//NameToCertificate: config["partnerCertPool"],
		//InsecureSkipVerify: true,
		},
	}

	req, err := http.NewRequest("PUT", devRec.PushUrl, body)
	if err != nil {
		return err
	}
	cli := http.Client{Transport: tr}
	resp, err := cli.Do(req)
	// Close the body, otherwise Memory leak!
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("Push Server Error")
	}
	return nil
}
