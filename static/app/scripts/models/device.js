/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'backbone',
  'jquery'
], function (_, Backbone, $) {
  'use strict';

  var Device = Backbone.Model.extend({
    LOCATION_TIMEOUT: 60 * 1000,

    defaults: {
      activity: 'blank',
      located: false
    },

    // Convert attributes to lowercase
    parse: function (resp, xhr) {
      return { id: resp.ID, name: resp.Name, url: resp.URL };
    },

    onWebSocketUpdate: function (message) {
      console.log('socket message received', message && message.data);

      if (message && message.data) {
        var data = JSON.parse(message.data);
        var attrs;

        if (data.Cmd) {
          attrs = this.parseCommand(data.Cmd);
        }

        if (data.Time > 0) {
          attrs.time = new Date(data.Time);
        }

        // Set the new attributes all at once so there's only one change event
        this.set(attrs);
      }
    },

    parseCommand: function (command) {
      /* jshint camelcase: false */

      var attrs;

      if (command.e) {
        attrs = this.parseEraseCommand(command);
      } else if (command.has_passcode) {
        attrs = this.parseHasPasscodeCommand(command);
      } else if (command.l) {
        attrs = this.parseLockCommand(command);
      } else if (command.r) {
        attrs = this.parseRingCommand(command);
      } else if (command.t) {
        attrs = this.parseTrackCommand(command);
      }

      return attrs;
    },

    parseEraseCommand: function (command) {
      this.trigger('command:received:erase', command.e);

      return {};
    },

    parseHasPasscodeCommand: function (command) {
       /* jshint camelcase: false */

      var hasPasscodeCommand = command.has_passcode;

      this.trigger('command:received:hasPasscode', hasPasscodeCommand);

      return {
        hasPasscode: hasPasscodeCommand.has_passcode
      };
    },

    parseLockCommand: function (command) {
      this.trigger('command:received:lock', command.l);

      return {};
    },

    parseRingCommand: function (command) {
      this.trigger('command:received:ring', command.r);

      return {};
    },

    parseTrackCommand: function(command) {
      var trackCommand = command.t;
      var attrs = {};

      if (trackCommand.ok && trackCommand.la && trackCommand.lo) {
        // Clear location timeout
        clearTimeout(this.locationTimeout);

        attrs.latitude = trackCommand.la;
        attrs.longitude = trackCommand.lo;
        attrs.located = true;

        // Lose location after 60 seconds of no location updates
        this.locationTimeout = setTimeout(_.bind(this.locationTimedout, this), this.LOCATION_TIMEOUT);
      }

      this.trigger('command:received:track', trackCommand);

      return attrs;
    },

    locationTimedout: function () {
      this.set('located', false);
    },

    listenForUpdates: function () {
      this.socket = new WebSocket(this.get('url'));
      this.socket.onmessage = this.onWebSocketUpdate.bind(this);

      // WebSocket debugging for the debuggers
      console.log('socket opening...');

      this.socket.onopen = function () {
        console.log('socket open.');
      };

      this.socket.onerror = function (error) {
        console.log('socket error:', error);
      };

      this.socket.onclose = function (close) {
        console.log('socket close:', close);
      };
    },

    stopListening: function () {
      this.socket.close();
    },

    sendCommand: function (command) {
      this.trigger('command:sent', command);

      return $.ajax({
        data: command.toJSON(),
        dataType: 'json',
        type: 'PUT',
        url: '/1/queue/' + this.get('id')
      });
    }
  });

  return Device;
});
