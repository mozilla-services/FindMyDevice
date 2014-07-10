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
        .findByCssSelector('.button.play-sound a')
          .click()
        .end()
        .findByCssSelector('#modal button.play-sound')
          .click()
        .end()
        .findByCssSelector('#notifier')
          .text()
          .then(function (text) {
            assert.strictEqual(text, 'Your device is ringing.');
          })
        .end();
    }
  });
});
