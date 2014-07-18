/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var fs = require('fs');
var express = require('express');
var rest = require('restler');
var ini = require('ini');
var pg = require('pg.js');

var app = express();
var config = ini.parse(fs.readFileSync('../config.ini', 'utf-8'));
var pgConfig = {
  database: config['db.db'],
  host: config['db.host'],
  user: config['db.user'],
  password: config['db.password']
};
var server;

var PORT = 8001;
var DEVICE_ID = '2308f72d407c24b48045acb890371a83';
var HAWK_SECRET = 'FAAAAAAAAAAAAAAAAAAAKE==';
var PUSH_URL = 'http://localhost:' + PORT + '/ping';
var ACCEPTS = 'telrh';
var LOCKABLE = 'f';
var LOGGED_IN = 'f';
var USER_ID = '15c664adab0c11789bf0c988071055e29794a599b87e34ac0b141639017e5f69';
var USER_NAME = 'fmd-functional-test-user';
var REMOTE_BASE_URL = 'http://localhost:8000/1';

// Ideally this would use the real registration endpoint but this cuts out a lot of complexity that
// we don't care about for these tests. Unfortunately this is a bit brittle.
function register (callback) {
  pg.connect(pgConfig,
    function(err, client, done) {
      if (err) {
        console.error('Failed to connect to postgres.', err);

        // No db connection means we aren't going any further. Aborting mission...
        process.exit();
      }

      // Create deviceinfo record
      client.query('INSERT INTO deviceinfo (deviceid, lockable, loggedin, lastexchange, hawksecret, pushurl, accepts) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [ DEVICE_ID, LOCKABLE, LOGGED_IN, new Date(), HAWK_SECRET, PUSH_URL, ACCEPTS ],
        function(err, result) {
          if (err) {
            console.error('- Failed to create deviceinfo record.', err);
          } else {
            console.info('- Inserted deviceinfo record.');
          }

          // Create usertodevicemap
          client.query('INSERT INTO usertodevicemap (userid, deviceid, name) VALUES ($1, $2, $3)',
            [ USER_ID, DEVICE_ID, USER_NAME ],
            function(err, result) {
              if (err) {
                console.error('- Failed to create usertodevicemap record.', err);
              } else {
                console.info('- Inserted usertodevicemap record.');
              }

              done();
              callback();
            }
          );
        }
      );
    }
  );
}

// Remove fake device from the db
function unregister (callback) {
  pg.connect(pgConfig,
    function(err, client, done) {
      if (err) {
        console.error('Failed to connect to postgres.', err);
      }

      // Create deviceinfo record
      client.query('DELETE FROM deviceinfo WHERE deviceid = $1', [ DEVICE_ID ], function(err, result) {
        if (err) {
          console.error('- Failed to delete deviceinfo record.', err);
        } else {
          console.info('- Deleted deviceinfo record.');
        }

        // Create usertodevicemap
        client.query('DELETE FROM usertodevicemap WHERE deviceid = $1', [ DEVICE_ID ], function(err, result) {
          if (err) {
            console.error('- Failed to delete usertodevicemap record.', err);
          } else {
            console.info('- Deleted usertodevicemap record.');
          }

          done();
          callback();
        });
      });
    }
  );
}

// Send command response to the server
function postCommand (postData) {
  console.info('Posting command...');
  console.info('Sending:', postData || '');

  rest.postJson(REMOTE_BASE_URL + '/cmd/' + DEVICE_ID, postData)
    .on('complete', function(data, response) {
      console.info('Received: ', data);

      var commandResponse = parseCommand(data);

      if (commandResponse) {
        postCommand(commandResponse);
      }
    }
  );
}

// Parse commands from the server
function parseCommand (command) {
  /* jshint camelcase: false */

  // Track command
  if (command.t) {
    // Make sure duration is included
    if (command.t.d) {
      return createCommandResponse('t', true, { la: 37.7895040, lo: -122.3890650, ti: Date.now(), has_passcode: false });
    } else {
      return createCommandResponse('t', false);
    }
  // Ring command
  } else if (command.r) {
    // Make sure duration and period are included
    if (command.r.d && command.r.p) {
      return createCommandResponse('r', true);
    } else {
      return createCommandResponse('r', false);
    }
  // Lock command
  } else if (command.l) {
    // Make sure message and code are included
    if (command.l.m && command.l.c) {
      return createCommandResponse('l', true);
    } else {
      return createCommandResponse('l', false);
    }
  // Erase command
  } else if (command.e) {
    return createCommandResponse('e', true);
  }
}

// Helper for creating command responses
function createCommandResponse (commandName, ok, attrs) {
  var command = {};

  // Command successful?
  command[commandName] = { ok: ok };

  // Copy over attributes if specified
  if (attrs) {
    for (var i in attrs) {
      if (attrs.hasOwnProperty(i)) {
        command[commandName][i] = attrs[i];
      }
    }
  }

  return command;
}

// Fake SimplePush endpoint
app.put('/ping', function(req, res){
  console.info('\nSimplePush received\n-------------------');

  postCommand();

  res.send('ok');
});

// Clean up db before exiting
process.on('SIGINT', function() {
  console.info('Cleaning up...');

  unregister(function () {
    process.exit();
  });
});

// Let's start accepting some phony commands
console.info('Phony in the house.');
console.info('Injecting phony device into the database...');

register(function () {
  server = app.listen(PORT, function() {
    console.info('Listening on port %d', server.address().port);
  });
});
