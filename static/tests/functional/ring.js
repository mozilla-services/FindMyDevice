/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'intern!bdd',
  'intern/chai!expect',
  'require'
], function (bdd, expect, require) {
  with(bdd) {
    describe('ring', function () {
      it('should ring the device', function () {
        return this.remote
          .get('http://localhost:8000/')
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
          .findByCssSelector('#notifier.active')
            .text()
            .then(function (text) {
              expect(text).to.equal('Your device is ringing.');
            })
          .end();
      });
    });
  }
});
