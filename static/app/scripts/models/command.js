/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'jquery'
], function ($) {
  'use strict';

  function Command() {
    // nothing to initialize
  }

  // Should be implemented by subclasses
  Command.prototype.asJSON = function() {
    return {};
  };

  Command.prototype.toJSON = function() {
    return JSON.stringify(this.asJSON());
  };

  Command.prototype.enqueue = function(deviceID) {
    $.ajax({
      data: this.toJSON(),
      dataType: 'json',
      type: 'PUT',
      url: '/0/queue/' + deviceID
    });
  };

  return Command;
});
