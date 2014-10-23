/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'jquery'
], function (_, $) {
  'use strict';

  var Localizer = {
    dictionary: {},

    fetch: function () {
      var xhr = $.ajax('/1/l10n/client.json');

      var self = this;

      xhr.fail(function () {
        self.dictionary = {};
      });

      xhr.done(function (data) {
        self.dictionary = data;
      });

      return xhr;
    },

    localize: function (input) {
      var output = this.dictionary[input];

      return output ? output : input;
    }
  };

  return Localizer;
});
