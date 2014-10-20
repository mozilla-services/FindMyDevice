/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// grunt task to extract strings.

const fs = require('fs');
const path = require('path');
const mkdirp = require('mkdirp');
const extract = require('jsxgettext-recursive');

// where to place the pot files.
const messagesOutputPath = path.join(__dirname, '..', 'locale', 'templates', 'LC_MESSAGES');

module.exports = function (grunt) {
  'use strict';

  grunt.registerTask('l10n-extract', 'Extract strings from templates for localization.', function () {
    var done = this.async();

    if (!fs.existsSync(messagesOutputPath)) {
      mkdirp.sync(messagesOutputPath);
    }

    var clientWalker = extract({
      'input-dir': path.join(__dirname, '..', 'app', 'scripts'),
      'output-dir': messagesOutputPath,
      'output': 'client.pot',
      'join-existing': false,
      'keyword': 'l',
      'parsers': {
        '.js': 'javascript',
        '.html': 'handlebars'
      }
    });

    clientWalker.on('end', function () {
      console.log('walking the server');
      var serverWalker = extract({
        'input-dir': path.join(__dirname, '..', 'app'),
        // Exclude everything except static/app/index.html
        'exclude': /^(?!.*static\/app\/index\.html$).*$/,
        'output-dir': messagesOutputPath,
        'output': 'server.pot',
        'join-existing': false,
        'parsers': {
          '.html': 'golang'
        }
      });

      serverWalker.on('end', function () {
        done();
      });
    });
  });
};

