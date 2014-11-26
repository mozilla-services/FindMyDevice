/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

require.config({
  paths: {
    jquery: '../bower_components/jquery/dist/jquery',
    backbone: '../bower_components/backbone/backbone',
    underscore: '../bower_components/underscore/underscore',
    text: '../bower_components/requirejs-text/text',
    mustache: '../bower_components/mustache/mustache',
    stache: '../bower_components/requirejs-mustache/stache',
    reconnectingWebsocket: '../bower_components/reconnectingWebsocket/reconnecting-websocket',
    parsley: '../bower_components/parsleyjs/dist/parsley'
  },
  shim: {
    underscore: {
      exports: '_'
    },
    backbone: {
      deps: [
        'underscore',
        'jquery'
      ],
      exports: 'Backbone'
    },
    parsley: {
      deps: [
        'jquery'
      ],
      exports: 'jQuery.Parsley'
    }
  }
});

require([
  'jquery',
  'backbone',
  'router',
  'collections/devices',
  'lib/localizer'
], function ($, Backbone, Router, Devices, Localizer) {
  // Bring on the globals
  window.devices = new Devices();

  // Fetch devices from the server
  $.when(window.devices.fetch(), Localizer.fetch()).always(function () {
    // Now that we have devices and strings we can start
    Backbone.history.start();
  });
});
