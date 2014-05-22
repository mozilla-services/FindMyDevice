/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'jquery',
  'backbone',
  'models/device',
  'views/location',
  'views/device_not_found'
], function ($, Backbone, Device, LocationView, DeviceNotFoundView) {
  'use strict';

  var Router = Backbone.Router.extend({
    routes: {
      '': 'showIndex'
    },

    initialize: function() {
      // Convert our embedded globals to models
      if (window.currentDevice) {
        window.currentDevice = new Device(window.currentDevice);
      }

      window.currentUser = new Backbone.Model(window.currentUser);
    },

    showIndex: function() {
      if (window.currentDevice) {
        this.showLocation();
      } else {
        this.showDeviceNotFound();
      }
    },

    showLocation: function() {
      this.setStage(new LocationView());
    },

    showDeviceNotFound: function() {
      this.setStage(new DeviceNotFoundView());
    },

    setStage: function(view) {
      $('#stage').html(view.render().el);

      view.afterInsert();
    }
  });

  // Return a singleton
  return new Router();
});
