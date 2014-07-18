/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'jquery'
], function (_, $) {
  'use strict';

  var Notifier = {
    AUTO_CLOSE_TIMEOUT: 5 * 1000,

    initialize: function () {
      this.$notifier = $('#notifier');
    },

    notify: function (message) {
      clearTimeout(this.autoCloseTimer);

      this.$notifier.html(message).addClass('active').fadeIn();

      this.autoCloseTimer = setTimeout(_.bind(this.close, this), this.AUTO_CLOSE_TIMEOUT);
    },

    close: function () {
      this.$notifier.removeClass('active').fadeOut();
    }
  };

  Notifier.initialize();

  return Notifier;
});
