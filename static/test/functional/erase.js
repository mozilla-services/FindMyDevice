/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'intern',
  'intern!bdd',
  'intern/chai!expect',
  'require'
], function (intern, bdd, expect, require) {
  'use strict';

  var URL = intern.config.fmd.url;
  var COMMAND_TIMEOUT = intern.config.fmd.commandTimeout;

  bdd.describe('erase', function () {
    bdd.it('should erase the device', function () {
      return this.remote
        .get(URL)
        // Wait up to COMMAND_TIMEOUT milliseconds for the device to respond
        .setFindTimeout(COMMAND_TIMEOUT)
        // Open erase dialog
        .findByCssSelector('.button.erase a')
          .click()
        .end()
        // Click Erase button
        .findByCssSelector('#modal button.erase')
          .click()
        .end()
        // Confirm erase
        .findByCssSelector('#modal button.erase.danger')
          .click()
        .end();
        // On erase there is no confirmation so we're done
    });
  });
});
