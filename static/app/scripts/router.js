/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'jquery',
  'backbone',
  'models/device',
  'views/device',
  'views/device_not_found'
], function ($, Backbone, Device, DeviceView, DeviceNotFoundView) {
  'use strict';

  var Router = Backbone.Router.extend({
    routes: {
      '': 'showIndex',
      'devices/:id': 'showDevice'
    },

    initialize: function () {
      // Redirect to root on any 401 errors.
      $(document).ajaxError(function (event, jqxhr, settings, exception) {
        if (jqxhr.status === 401) {
          window.location = '/';
        }
      });
    },

    showIndex: function () {
      if (window.devices.length > 0) {
        // Navigate to the device
        this.navigate('devices/' + window.devices.last().get('id'), { trigger: true });
      } else {
        this.showDeviceNotFound();
      }
    },

    showDevice: function (id) {
      this.setStage(new DeviceView({ model: window.devices.get(id) }));
    },

    showDeviceNotFound: function () {
      this.setStage(new DeviceNotFoundView());
    },

    setStage: function (view) {
      // Destroy the current view before replacing it
      if (this.currentView) {
        this.currentView.destroy();
      }

      this.currentView = view;

      $('#stage').html(this.currentView.render().el);

      this.currentView.afterInsert();
    }
  });

  // Return a singleton
  return new Router();
});
