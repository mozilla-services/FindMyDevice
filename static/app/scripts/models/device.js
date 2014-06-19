/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'backbone',
  'jquery',
  'lib/notifier'
], function (_, Backbone, $, Notifier) {
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
      var data = JSON.parse(message.data);

      if (data) {
        var updatedAttributes = {};

        updatedAttributes.hasPasscode = data.HasPasscode;

        if (data.Latitude > 0) {
          clearTimeout(this.locationTimeout);

          updatedAttributes.latitude = data.Latitude;
          updatedAttributes.longitude = data.Longitude;
          updatedAttributes.altitude = data.Altitude;
          updatedAttributes.located = true;

          // Lose location after 60 seconds of no location updates
          this.locationTimeout = setTimeout(_.bind(this.locationTimedout, this), this.LOCATION_TIMEOUT);
        }

        if (data.Time > 0) {
          updatedAttributes.time = new Date(data.Time);
        }

        console.log('device:updated', this.get('id'), updatedAttributes, message.data);

        // Just for notifications right now
        if (data.Cmd) {
          this.parseCommand(data.Cmd);
        }

        // Set the new attributes all at once so there's only one change event
        this.set(updatedAttributes);
      }
    },

    locationTimedout: function () {
      this.set('located', false);
    },

    parseCommand: function (command) {
      var message;

      if (command.r && command.r.ok) {
        message = 'playing a sound.';
      } else if (command.e && command.e.ok) {
        message = 'erasing.';
      } else if (command.l && command.l.ok) {
        message = 'in lost mode.';
      }

      if (message) {
        Notifier.notify('Your device is ' + message);
      }
    },

    listenForUpdates: function () {
      this.socket = new WebSocket(this.get('url'));
      this.socket.onmessage = this.onWebSocketUpdate.bind(this);
    },

    stopListening: function () {
      this.socket.close();
    },

    sendCommand: function (command) {
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
