/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'jquery'
], function (_, $) {
  'use strict';

  var Notifier = {
    initialize: function () {
      this.$notifier = $('#notifier');
    },

    notify: function (message) {
      clearTimeout(this.autoCloseTimer);

      this.$notifier.html(message).fadeIn();

      this.autoCloseTimer = setTimeout(_.bind(this.close, this), 5 * 1000);
    },

    close: function () {
      this.$notifier.fadeOut();
    }
  };

  Notifier.initialize();

  return Notifier;
});
