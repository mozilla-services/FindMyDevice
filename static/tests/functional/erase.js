/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'intern!bdd',
  'intern/chai!expect',
  'require'
], function (bdd, expect, require) {
  with(bdd) {
    describe('erase', function () {
      it('should erase the device', function () {
        return this.remote
          .get('http://localhost:8000/')
          // Wait up to 10 seconds for the device to respond
          .setFindTimeout(10000)
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
          .end()
          // Wait for confirmation
          .findByCssSelector('#notifier.active')
            .text()
            .then(function (text) {
              expect(text).to.equal('Your device is erasing.');
            })
          .end();
      });
    });
  }
});
