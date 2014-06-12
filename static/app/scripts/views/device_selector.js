/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/device_selector',
  'lib/modal_manager'
], function (BaseView, DeviceSelectorTemplate, ModalManager) {
  'use strict';

  var DeviceSelectorView = BaseView.extend({
    template: DeviceSelectorTemplate,

    events: {
      'click a': 'close'
    },

    initialize: function (options) {
      this.currentDevice = options.currentDevice;
    },

    close: function (event) {
      ModalManager.close();
    },

    getContext: function () {
      // Copy this into the local scope so it can be checked in isCurrentDevice
      var currentDevice = this.currentDevice;

      return {
        devices: window.devices.collect(function (d) { return d.attributes; }),
        isCurrentDevice: function () {
          // The device (this) is a bare object in this context
          return this.id === currentDevice.get('id');
        }
      };
    }
  });

  return DeviceSelectorView;
});
