/*global define*/

define([
  'views/base',
  'stache!templates/location'
], function (BaseView, LocationTemplate) {
  'use strict';

  var LocationView = BaseView.extend({
    template: LocationTemplate,

    events: {
      'click span.play-sound': 'playSound',
      'click span.lost-mode': 'lostMode',
      'click span.erase': 'erase'
    },

    playSound: function(event) {
      alert("PLAYING THE SOUND");
    },

    lostMode: function(event) {
      alert("LOSING THE DEVICE");
    },

    erase: function(event) {
      alert("ERASING THE DEVICE");
    },

    afterInsert: function() {
      L.mapbox.map('map', 'nchapman.hejm93ej');
    }
  });

  return LocationView;
});
