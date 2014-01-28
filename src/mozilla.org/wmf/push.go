/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package wmf

import (
    "mozilla.org/wmf/storage"
    "bytes"
    "net/http"
    "errors"
)

func SendPush(devRec *storage.Device) error {
	// wow, so very tempted to make sure this matches the known push server.
	bbody := []byte{}
	body := bytes.NewReader(bbody)
	req, err := http.NewRequest("PUT", devRec.PushUrl, body)
	if err != nil {
		return err
	}
	cli := http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("Push Server Error")
	}
	return nil
}


