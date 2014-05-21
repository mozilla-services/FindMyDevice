/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'models/command'
], function (Command) {
  'use strict';

  function MessageCommand(message, phoneNumber) {
    this.message = message;
    this.phoneNumber = phoneNumber;
  }

  // Extend Command
  MessageCommand.prototype = new Command();

  MessageCommand.prototype.asJSON = function() {
    return {
      m: {
        m: this.message,
        n: this.phoneNumber
      }
    };
  };

  return MessageCommand;
});
