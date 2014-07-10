/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

 define([
  'intern!object',
  'intern/chai!assert',
  'require'
], function (registerSuite, assert, require) {
  registerSuite({
    name: 'ring',

    'ring device': function () {
      return this.remote
        .get('http://localhost:8000/')
        .setFindTimeout(10000)
        .findByCssSelector('.button.play-sound a')
          .click()
        .end()
        .findByCssSelector('#modal button.play-sound')
          .click()
        .end()
        .findByCssSelector('#notifier.active')
          .text()
          .then(function (text) {
            assert.strictEqual(text, 'Your device is ringing.');
          })
        .end();
    }
  });
});
