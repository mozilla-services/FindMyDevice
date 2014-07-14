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

  bdd.describe('ring', function () {
    bdd.it('should ring the device', function () {
      return this.remote
        .get(URL)
        // Wait up to 10 seconds for the device to respond
        .setFindTimeout(10000)
        // Open play sound dialog
        .findByCssSelector('.button.play-sound a')
          .click()
        .end()
        // Click Ring Device button
        .findByCssSelector('#modal button.play-sound')
          .click()
        .end()
        // Wait for confirmation
        .sleep(100)
        .findByCssSelector('#notifier.active')
          .text()
          .then(function (text) {
            expect(text).to.equal('Your device is ringing.');
          })
        .end();
    });
  });
});
