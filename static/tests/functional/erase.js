define([
  'intern!object',
  'intern/chai!assert',
  'require'
], function (registerSuite, assert, require) {
  registerSuite({
    name: 'erase',

    'erase device': function () {
      return this.remote
        .get('http://localhost:8000/')
        .setFindTimeout(10000)
        .findByCssSelector('.button.erase a')
          .click()
        .end()
        .findByCssSelector('#modal button.erase')
          .click()
        .end()
        .findByCssSelector('#modal button.erase.danger')
          .click()
        .end()
        .findByCssSelector('#notifier.active')
          .text()
          .then(function (text) {
            assert.strictEqual(text, 'Your device is erasing.');
          })
        .end();
    }
  });
});
