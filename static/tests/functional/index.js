/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

 define([
  'intern!object',
  'intern/chai!assert',
  'require'
], function (registerSuite, assert, require) {
  registerSuite({
    name: 'index',

    'shows welcome to unauthenticated users': function () {
      return this.remote
        .get('http://localhost:8000/')
        .findByCssSelector('h1')
        .getVisibleText()
        .then(function (text) {
            assert.strictEqual(text, "Rumor has it that you can't find your device.");
        });
    },

    'signs in': function () {
      return this.remote
        .get('http://localhost:8000/')
        .setFindTimeout(10000)
        .findByCssSelector('#login a')
          .click()
        .end()
        .findByCssSelector('input.email')
          .type('fmd-functional-test-user@mailinator.com')
        .end()
        .findByCssSelector('input.password')
          .type('fmdfxa123')
        .end()
        .findByCssSelector('#submit-btn')
          .click()
        .end()
        .findByCssSelector('.fmd #stage h1')
          .text()
          .then(function (text) {
            assert.strictEqual(text, 'fmd-functional-test-user');
          })
        .end();
    }
  });
});
