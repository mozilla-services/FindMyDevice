define([
  'intern!object',
  'intern/chai!assert',
  'require'
], function (registerSuite, assert, require) {
  registerSuite({
    name: 'index',

    'unauthenticated': function () {
      return this.remote
        .get('http://localhost:8080/')
        .findByCssSelector('h1')
        .getVisibleText()
        .then(function (text) {
            assert.strictEqual(text, "Rumor has it that you can't find your device.");
        });
    }
  });
});
