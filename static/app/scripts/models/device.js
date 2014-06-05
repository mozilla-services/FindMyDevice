/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'backbone',
  'jquery'
], function (Backbone, $) {
  'use strict';

  var Device = Backbone.Model.extend({
    // Convert attributes to lowercase
    parse: function(resp, xhr) {
      return { id: resp.ID, name: resp.Name, url: resp.URL };
    },

    onWebSocketUpdate: function(message) {
      var data = JSON.parse(message.data);

      if (data) {
        var updatedAttributes = {};

        updatedAttributes.time = data.Time;
        updatedAttributes.lockable = data.Lockable;

        if (data.Latitude > 0) {
          updatedAttributes.latitude = data.Latitude;
          updatedAttributes.longitude = data.Longitude;
          updatedAttributes.altitude = data.Altitude;
        }

        console.log('device:updated', this.get('id'), updatedAttributes, message.data);

        // Set the new attributes all at once so that we only get one change event
        this.set(updatedAttributes);
      }
    },

    listenForUpdates: function() {
      // TODO: replace this with something configurable
      this.socket = new WebSocket(this.get('url'));
      this.socket.onmessage = this.onWebSocketUpdate.bind(this);
    },

    sendCommand: function(command) {
      return $.ajax({
        data: command.toJSON(),
        dataType: 'json',
        type: 'PUT',
        url: '/0/queue/' + this.get('id')
      });
    }
  });

  return Device;
});
