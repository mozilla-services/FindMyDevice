/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'backbone',
  'jquery',
  'reconnectingWebsocket'
], function (_, Backbone, $, ReconnectingWebsocket) {
  'use strict';

  var Device = Backbone.Model.extend({
    LOCATION_TIMEOUT: 60 * 1000,
    SOCKET_KEEP_ALIVE_INTERVAL: 45 * 1000,

    defaults: {
      activity: 'blank',
      located: false
    },

    // Convert attributes to lowercase
    parse: function (resp, xhr) {
      return { id: resp.ID, name: resp.Name, url: resp.URL };
    },

    onWebSocketUpdate: function (message) {
      console.log('ws:message', message && message.data);

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
        clearTimeout(this.locationTimer);

        attrs.latitude = trackCommand.la;
        attrs.longitude = trackCommand.lo;
        attrs.located = true;

        // Lose location after 60 seconds of no location updates
        this.locationTimer = setTimeout(_.bind(this.locationTimedout, this), this.LOCATION_TIMEOUT);
      }

      this.trigger('command:received:track', trackCommand);

      return attrs;
    },

    locationTimedout: function () {
      this.set('located', false);
    },

    listenForUpdates: function () {
      this.socket = new ReconnectingWebsocket(this.get('url'));
      this.socket.onmessage = _.bind(this.onWebSocketUpdate, this);

      // DEBUG: WebSocket debugging for the debuggers
      console.log('ws:opening');

      this.socket.onopen = function () {
        console.log('ws:open');
      };

      this.socket.onerror = function (error) {
        console.log('ws:error', error);
      };

      this.socket.onclose = function (close) {
        console.log('ws:close', close);
      };

      this.socketKeepAliveTimer = setInterval(_.bind(this.keepSocketAlive, this), this.SOCKET_KEEP_ALIVE_INTERVAL);
    },

    keepSocketAlive: function () {
      this.socket.send('');
    },

    stopListening: function () {
      clearTimeout(this.socketKeepAliveTimer);

      this.socket.close();
    },

    sendCommand: function (command) {
      var commandJSON = command.toJSON();
      var csrfToken = $('meta[name=token]').attr('content');

      this.trigger('command:sent', commandJSON);

      return $.ajax({
        data: commandJSON,
        dataType: 'json',
        headers: { 'X-CSRFTOKEN': csrfToken },
        type: 'PUT',
        url: '/1/queue/' + this.get('id')
      });
    }
  });

  return Device;
});
