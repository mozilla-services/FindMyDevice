/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package wmf

import (
	"mozilla.org/wmf/storage"
	"mozilla.org/util"
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"errors"
)

func SendPush(devRec *storage.Device, config *util.JsMap) error {
	// wow, so very tempted to make sure this matches the known push server.
	bbody := []byte{}
	body := bytes.NewReader(bbody)
	fmt.Printf("### sending to %s\n", devRec.PushUrl)
	/* If your server is not trustfully signed, the following will fail.
		If partners are unable/unwilling to trustfully sign servers, 
		it is possible to skip validation by using 
		&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		however that is not advised as a general policy for damn good reasons.
	*/
	//TODO: for get the partner's cert pool from the config (based on tld)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			//RootCAs: partnerCertPool,
			//InsecureSkipVerify: true,
		},
	}

	req, err := http.NewRequest("PUT", devRec.PushUrl, body)
	if err != nil {
		return err
	}
	cli := http.Client{Transport: tr}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("Push Server Error")
	}
	return nil
}
