/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// grunt task to create .json files out of .po files.
// .po files are expected to already be downloaded.

const path = require('path');
const util = require('util');

module.exports = function (grunt) {
  'use strict';

  grunt.config('po2json', {
    options: {
      format: 'raw',
      fuzzy: true,
      /*jshint camelcase: false*/
      output_filename: function (file) {
        /**
         * the files are stored in the locale subdirectory with a directory
         * structure of:
         * locale/
         *       <locale_name>/
         *                    LC_MESSAGES/
         *                               server.po
         *                               client.po
         *
         * Each locale is stored in its own subdirectory in the output i18n
         * directory.
         **/
        var matches = /^locale\/([^\/]+)\/LC_MESSAGES\/(.*)$/.exec(file);

        // Lowercase locale names for server side simplicity
        var locale = matches[1].toLowerCase();
        var filename = matches[2];

        // get rid of the .po extension, replace with .json
        filename = path.basename(filename, '.po') + '.json';

        return path.join(locale, filename);
      },
      output_transform: function (data) {
        var transformed = {};

        for (var msgid in data) {
          var translation = data[msgid];

          if (util.isArray(translation) && translation.length >= 2) {
            translation = translation[1];
          }

          transformed[msgid] = translation;
        }

        return transformed;
      }
    },
    all: {
      src: ['<%= yeoman.strings.dest %>/**/*.po'],
      dest: '<%= yeoman.app %>/l10n'
    },
    template: {
      src: ['<%= yeoman.strings.dest %>/**/*.pot'],
      dest: '<%= yeoman.tmp %>/l10n'
    }
  });
};


