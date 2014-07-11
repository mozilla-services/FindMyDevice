/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var express = require('express');
var rest = require('restler');

var app = express();

var BASE_URL = 'http://localhost:8000/1';
var DEVICE_ID = 'cb6107ce4050dab8800325a6a7c2fe97';

function postCommand(postData) {
  console.log('Posting command...');
  console.log('Sending:', postData || '');

  rest.postJson(BASE_URL + '/cmd/' + DEVICE_ID, postData)
    .on('complete', function(data, response) {
      console.log('Received: ', data);

      var commandResponse = generateCommandResponse(data);

      if (commandResponse) {
        postCommand(commandResponse);
      }
    }
  );
}

function generateCommandResponse (command) {
  /* jshint camelcase: false */

  if (command.t) {
    return { t: { ok: true, la: 37.7895040, lo: -122.3890650, ti: Date.now(), has_passcode: false } };
  } else if (command.r) {
    return { r: { ok: true } };
  } else if (command.l) {
    return { l: { ok: true } };
  } else if (command.e) {
    return { e: { ok: true } };
  }
}

// Fake SimplePush endpoint
app.put('/ping', function(req, res){
  console.log('\nSimplePush received\n-------------------');

  postCommand();

  res.send('ok');
});

// Let's start sending some phony commands
var server = app.listen(8001, function() {
  console.log('Phony is at your service on port %d.', server.address().port);
});
