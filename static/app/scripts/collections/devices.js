/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'backbone',
  'jquery',
  'models/device'
], function (Backbone, $, Device) {
  'use strict';

  var DevicesCollection = Backbone.Collection.extend({
    model: Device,
    url: '/1/devices/',

    // Extract root devices array
    parse: function (resp, xhr) {
      return resp.devices;
    }
  });

  return DevicesCollection;
});
