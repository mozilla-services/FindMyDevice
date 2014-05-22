/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

require.config({
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
    }
  },
  paths: {
    jquery: '../bower_components/jquery/dist/jquery',
    backbone: '../bower_components/backbone/backbone',
    underscore: '../bower_components/underscore/underscore',
    text: '../bower_components/requirejs-text/text',
    mustache: '../bower_components/mustache/mustache',
    stache: '../bower_components/requirejs-mustache/stache'
  }
});

require([
  'backbone',
  'router'
], function (Backbone, Router) {
  Backbone.history.start();

  // Temporary logout handing
  $(document).on('click', 'a.signout', function(event) {
    event.preventDefault();

    navigator.id.watch({
      onlogin: function() {
        // we're not handling login here.
      },

      onlogout: function() {
        document.cookie="user=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
        document.location.reload();
      }
    });

    navigator.id.logout();
  })
});
