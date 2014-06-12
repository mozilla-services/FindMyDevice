/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'backbone'
], function (Backbone) {
  'use strict';

  var Command = Backbone.Model.extend({
    asJSON: function () {
      return this.attributes;
    },

    toJSON: function () {
      return JSON.stringify(this.asJSON());
    }
  });

  return Command;
});
