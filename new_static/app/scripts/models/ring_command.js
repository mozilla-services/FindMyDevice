/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'models/command'
], function (Command) {
  'use strict';

  function RingCommand(duration) {
    this.duration = duration;
  }

  // Inherit from Command
  RingCommand.prototype = new Command();

  RingCommand.prototype.asJSON = function() {
    return {
      r: {
        d: this.duration
      }
    };
  };

  return RingCommand;
});
