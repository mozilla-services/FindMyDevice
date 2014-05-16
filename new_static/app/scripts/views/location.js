/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/location',
  'lib/modal_manager',
  'views/play_sound',
  'views/lost_mode',
  'views/erase'
], function (BaseView, LocationTemplate, ModalManager, PlaySoundView, LostModeView, EraseView) {
  'use strict';

  var LocationView = BaseView.extend({
    template: LocationTemplate,

    events: {
      'click span.play-sound': 'openPlaySound',
      'click span.lost-mode': 'openLostMode',
      'click span.erase': 'openErase'
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
      var map = L.mapbox.map('map', 'nchapman.hejm93ej', { zoomControl: false });

      // Position zoom controls
      new L.Control.Zoom({ position: 'topright' }).addTo(map);
    }
  });

  return LocationView;
});
