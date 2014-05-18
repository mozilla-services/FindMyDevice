/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'models/command'
], function (Command) {
  'use strict';

  function LockCommand(code, message) {
    this.code = code;
    this.message = message;
  }

  // Extend Command
  LockCommand.prototype = new Command();

  LockCommand.prototype.asJSON = function() {
    return {
      l: {
        c: this.code,
        m: this.message
      }
    };
  };

  return LockCommand;
});
