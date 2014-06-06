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
      this.model = currentDevice;

      // Listen for model changes
      this.listenTo(this.model, 'change:latitude', this.updateMapPosition);

      this.startTracking();
    },

    openPlaySound: function (event) {
      event.stopPropagation();

      ModalManager.open(new PlaySoundView(), $(event.target).closest('span.button'));
    },

    openLostMode: function (event) {
      event.stopPropagation();

      ModalManager.open(new LostModeView({ device: this.model }), $(event.target).closest('span.button'));
    },

    openErase: function (event) {
      event.stopPropagation();

      ModalManager.open(new EraseView(), $(event.target).closest('span.button'));
    },

    afterInsert: function () {
      // Setup the map
      this.map = L.mapbox.map('map', 'nchapman.hejm93ej', { zoomControl: false });

      // Position zoom controls
      new L.Control.Zoom({ position: 'topright' }).addTo(this.map);
    },

    startTracking: function() {
      currentDevice.listenForUpdates();

      currentDevice.sendCommand(new TrackCommand({ duration: 60, period: 10 }));
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
              // These are purposely reversed in this context
              coordinates: [longitude, latitude]
            },
            properties: {}
          })
        });

        this.marker.addTo(this.map);

        // Set view to new latitude and longitude and zoom to 15
        this.map.setView([latitude, longitude], 15);
      } else {
        this.marker.setLatLng([latitude, longitude]);
        this.map.panTo([latitude, longitude]);
      }
    }
  });

  return LocationView;
});
