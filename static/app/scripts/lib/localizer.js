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

    // Fetches the localized strings from the server and saves them for later
    fetch: function () {
      var xhr = $.ajax('/1/l10n/client.json');

      var self = this;

      xhr.fail(function () {
        // Reset the dictionary on failure
        self.dictionary = {};
      });

      xhr.done(function (data) {
        self.dictionary = data;
      });

      return xhr;
    },

    // Looks up the English string in the dictionary.
    // Returns the English string if nothing is found.
    localize: function (input) {
      var output = this.dictionary[input];

      // null or empty string returns input
      return output && output.trim().length ? output : input;
    }
  };

  return Localizer;
});
