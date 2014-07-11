/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'intern!bdd',
  'intern/chai!expect',
  'require'
], function (bdd, expect, require) {
  'use strict';

  bdd.describe('index', function () {
    bdd.it('should welcome unauthenticated users', function () {
      return this.remote
        .get('http://localhost:8000/')
        // Check heading text to see that we're signed out
        .findByCssSelector('h1')
          .text()
          .then(function (text) {
            expect(text).to.equal('Rumor has it that you can\'t find your device.');
          });
    });

    bdd.it('should allow sign in', function () {
      return this.remote
        .get('http://localhost:8000/')
        // Wait for up to 10 seconds for the FxA sign in step
        .setFindTimeout(10000)
        // Click sign in link
        .findByCssSelector('#login a')
          .click()
        .end()
        // -> Context: FxA sign in
        // Fill in the email address
        .findByCssSelector('input.email')
          .type('fmd-functional-test-user@mailinator.com')
        .end()
        // Fill in the password
        .findByCssSelector('input.password')
          .type('fmdfxa123')
        .end()
        // Click the sign in button
        .findByCssSelector('#submit-btn')
          .click()
        .end()
        // Check the FMD header to make sure we're now signed in
        .findByCssSelector('.fmd #stage h1')
          .text()
          .then(function (text) {
            expect(text).to.equal('fmd-functional-test-user');
          })
        .end();
    });
  });
});
