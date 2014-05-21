/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'models/command'
], function (Command) {
  'use strict';

  function TrackCommand(duration, period) {
    this.duration = duration;
    this.period = period;
  }

  // Extend Command
  TrackCommand.prototype = new Command();

  TrackCommand.prototype.asJSON = function() {
    return {
      t: {
        d: this.duration,
        p: this.period
      }
    };
  };

  return TrackCommand;
});
