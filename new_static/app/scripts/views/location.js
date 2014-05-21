/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'backbone',
  'views/base',
  'stache!templates/location',
  'models/device',
  'models/track_command',
  'lib/modal_manager',
  'views/play_sound',
  'views/lost_mode',
  'views/erase'
], function (Backbone, BaseView, LocationTemplate, Device, TrackCommand, ModalManager, PlaySoundView, LostModeView, EraseView) {
  'use strict';

  var LocationView = BaseView.extend({
    template: LocationTemplate,

    events: {
      'click span.play-sound': 'openPlaySound',
      'click span.lost-mode': 'openLostMode',
      'click span.erase': 'openErase'
    },

    initialize: function() {
      this.model = new Device(window.currentDevice);

      this.model.listenForUpdates();

      var command = new TrackCommand(30, 10);

      command.enqueue(this.model.get('id'));

      this.listenTo(this.model, 'change:latitude', this.updateMapPosition);
    },

    openPlaySound: function (event) {
      ModalManager.open(new PlaySoundView());
    },

    openLostMode: function (event) {
      ModalManager.open(new LostModeView());
    },

    openErase: function (event) {
      ModalManager.open(new EraseView());
    },

    afterInsert: function () {
      // Setup the map
      this.map = L.mapbox.map('map', 'nchapman.hejm93ej', { zoomControl: false });

      // Position zoom controls
      new L.Control.Zoom({ position: 'topright' }).addTo(this.map);
    },

    updateMapPosition: function() {
      var latitude = this.model.get('latitude');
      var longitude = this.model.get('longitude');

      // Create the marker if it doesn't exist
      if (!this.marker) {
        this.marker = L.marker([latitude, longitude], {
          icon: L.mapbox.marker.icon({
            type: 'Feature',
            geometry: {
              type: 'Point',
              // These are purprosely reversed in this context
              coordinates: [longitude, latitude]
            },
            properties: {}
          })
        });

        this.marker.addTo(this.map);
      } else {
        // TODO: Make sure this really works...
        this.marker.setLatLng(L.latLng(latitude, longitude));
      }

      // Set view to new latitude and longitude and zoom to 15
      this.map.setView([latitude, longitude], 15);
    }
  });

  return LocationView;
});
