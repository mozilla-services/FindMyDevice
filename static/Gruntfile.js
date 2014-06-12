/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var path = require('path');

// # Globbing
// for performance reasons we're only matching one level down:
// 'test/spec/{,*/}*.js'
// use this if you want to match all subfolders:
// 'test/spec/**/*.js'
// templateFramework: 'mustache'

module.exports = function (grunt) {
  'use strict';

  var LIVERELOAD_PORT = 35729;
  var SERVER_PORT = 9000;

  var lrSnippet = require('connect-livereload')({port: LIVERELOAD_PORT});
  var mountFolder = function (connect, dir) {
    return connect.static(path.resolve(dir));
  };

  // show elapsed time at the end
  require('time-grunt')(grunt);

  // load all grunt tasks
  require('load-grunt-tasks')(grunt);

  // configurable paths
  var yeomanConfig = {
    app: 'app',
    dist: 'dist',
    test: 'test',
    tmp: '.tmp'
  };

  grunt.initConfig({
    yeoman: yeomanConfig,

    // AUTOPREFIXER TASK
    autoprefixer: {
      options: {
        browsers: ['> 1%', 'last 5 versions', 'ff >= 16', 'Explorer >= 8']
      },
      dist: {
        files: [{
          expand: true,
          cwd: '<%= yeoman.tmp %>/styles/',
          src: '{,*/}*.css',
          dest: '<%= yeoman.tmp %>/styles/'
        }]
      },
      dev: {
        files: [{
          expand: true,
          cwd: '<%= yeoman.app %>/styles/',
          src: '{,*/}*.css',
          dest: '<%= yeoman.app %>/styles/'
        }]
      }
    },

    // BOWER TASK
    bower: {
      all: {
        rjsConfig: '<%= yeoman.app %>/scripts/main.js'
      }
    },

    // CLEAN TASK
    clean: {
      dist: [
        '<%= yeoman.tmp %>',
        '<%= yeoman.dist %>/*'
      ],
      server: '<%= yeoman.tmp %>'
    },

    // CONNECT TASK
    connect: {
      options: {
        port: SERVER_PORT,
        // change this to '0.0.0.0' to access the server from outside
        hostname: 'localhost'
      },
      livereload: {
        options: {
          middleware: function (connect) {
            return [
              lrSnippet,
              mountFolder(connect, yeomanConfig.tmp),
              mountFolder(connect, yeomanConfig.app)
            ];
          }
        }
      },
      test: {
        options: {
          port: 9001,
          middleware: function (connect) {
            return [
              lrSnippet,
              mountFolder(connect, yeomanConfig.tmp),
              mountFolder(connect, yeomanConfig.test),
              mountFolder(connect, yeomanConfig.app)
            ];
          }
        }
      },
      dist: {
        options: {
          middleware: function (connect) {
            return [
              mountFolder(connect, yeomanConfig.dist)
            ];
          }
        }
      }
    },

    // COPY TASK
    copy: {
      dist: {
        files: [{
          expand: true,
          dot: true,
          cwd: '<%= yeoman.app %>',
          dest: '<%= yeoman.dist %>',
          src: [
            '*.{ico,txt}',
            '.htaccess',
            'images/{,*/}*.{webp,gif}',
            'styles/fonts/{,*/}*.*'
          ]
        }]
      }
    },

    // COPYRIGHT TASK
    copyright: {
      app: {
        options: {
          pattern: 'This Source Code Form is subject to the terms of the Mozilla Public'
        },
        src: [
          '<%= jshint.all %>'
        ]
      }
    },

    // CSSLINT TASK
    csslint: {
      strict: {
        options: {
          'csslintrc': '.csslintrc'
        },
        src: [
          '{<%= yeoman.tmp %>,<%= yeoman.app %>}/styles/**/*.css'
        ]
      }
    },

    // CSSMIN TASK
    cssmin: {
      dist: {
        files: {
          '<%= yeoman.dist %>/styles/main.css': [
            '<%= yeoman.app %>/bower_components/normalize-css/normalize.css',
            '<%= yeoman.tmp %>/styles/{,*/}*.css',
            '<%= yeoman.app %>/styles/{,*/}*.css'
          ]
        }
      }
    },

    // HTMLMIN TASK
    htmlmin: {
      dist: {
        options: {
          /*removeCommentsFromCDATA: true,
          // https://github.com/yeoman/grunt-usemin/issues/44
          //collapseWhitespace: true,
          collapseBooleanAttributes: true,
          removeAttributeQuotes: true,
          removeRedundantAttributes: true,
          useShortDoctype: true,
          removeEmptyAttributes: true,
          removeOptionalTags: true*/
        },
        files: [{
          expand: true,
          cwd: '<%= yeoman.app %>',
          src: '*.html',
          dest: '<%= yeoman.dist %>'
        }]
      }
    },

    // IMAGEMIN TASK
    imagemin: {
      dist: {
        files: [{
          expand: true,
          cwd: '<%= yeoman.app %>/images',
          src: '{,*/}*.{png,jpg,jpeg}',
          dest: '<%= yeoman.dist %>/images'
        }]
      }
    },

    // JSCS TASK
    jscs: {
      options: {
        config: '.jscsrc'
      },
      all: '<%= jshint.all %>'
    },

    // JSHINT TASK
    jshint: {
      options: {
        jshintrc: '.jshintrc',
        reporter: require('jshint-stylish')
      },
      all: [
        'Gruntfile.js',
        '<%= yeoman.app %>/scripts/{,*/}*.js',
        '!<%= yeoman.app %>/scripts/vendor/*',
        '<%= yeoman.test %>/spec/{,*/}*.js'
      ]
    },

    // OPEN TASK
    open: {
      server: {
        path: 'http://localhost:<%= connect.options.port %>'
      },
      test: {
        path: 'http://localhost:<%= connect.test.options.port %>'
      }
    },

    // REQUIREJS TASK
    requirejs: {
      dist: {
        options: {
          almond: true,
          baseUrl: '<%= yeoman.app %>/scripts',
          dir: '<%= yeoman.dist %>/scripts',
          mainConfigFile: '<%= yeoman.app %>/scripts/main.js',
          name: 'main',
          preserveLicenseComments: false,
          removeCombined: true,
          replaceRequireScript: [{
            files: ['<%= yeoman.dist %>/index.html'],
            module: 'main',
            modulePath: '/scripts/almond' // `almond: true` causes the output file to be named almond.js
          }],
          stubModules: ['text', 'stache'],
          useStrict: true
        }
      }
    },

    // REV TASK
    rev: {
      dist: {
        files: {
          src: [
            '<%= yeoman.dist %>/scripts/{,*/}*.js',
            '<%= yeoman.dist %>/styles/{,*/}*.css',
            '<%= yeoman.dist %>/images/{,*/}*.{png,jpg,jpeg,gif,webp}',
            '/styles/fonts/{,*/}*.*'
          ]
        }
      }
    },

    // SASS TASK
    sass: {
      options: {
        imagePath: '../images'
      },
      dist: {
        files: {
          '<%= yeoman.tmp %>/styles/main.css': '<%= yeoman.app %>/styles/main.scss'
        }
      },
      dev: {
        files: {
          '<%= yeoman.app %>/styles/main.css': '<%= yeoman.app %>/styles/main.scss'
        }
      }
    },

    // USEMIN TASK
    usemin: {
      html: ['<%= yeoman.dist %>/{,*/}*.html'],
      css: ['<%= yeoman.dist %>/styles/{,*/}*.css'],
      options: {
        dirs: ['<%= yeoman.dist %>']
      }
    },

    // USEMINPREPARE TASK
    useminPrepare: {
      html: '<%= yeoman.app %>/index.html',
      options: {
        dest: '<%= yeoman.dist %>'
      }
    },

    // WATCH TASK
    watch: {
      options: {
        nospawn: true,
        livereload: true
      },
      sass: {
        files: ['<%= yeoman.app %>/styles/{,*/}*.scss'],
        tasks: [
          'sass:dev',
          'autoprefixer:dev'
        ],
        options: {
          atBegin: true
        }
      },
      livereload: {
        options: {
          livereload: LIVERELOAD_PORT
        },
        files: [
          '<%= yeoman.app %>/*.html',
          '{<%= yeoman.tmp %>,<%= yeoman.app %>}/styles/{,*/}*.css',
          '{<%= yeoman.tmp %>,<%= yeoman.app %>}/scripts/{,*/}*.js',
          '<%= yeoman.app %>/images/{,*/}*.{png,jpg,jpeg,gif,webp}',
          '<%= yeoman.app %>/scripts/templates/*.{ejs,mustache,hbs}',
          '<%= yeoman.test %>/spec/**/*.js'
        ]
      },
      test: {
        files: [
          '<%= yeoman.app %>/scripts/{,*/}*.js',
          '<%= yeoman.test %>/spec/**/*.js'
        ],
        tasks: ['test:true']
      }
    }
  });

  // BUILD TASK
  grunt.registerTask('build', [
    'clean:dist',
    'css',
    'useminPrepare',
    'imagemin',
    'htmlmin',
    'concat',
    'cssmin',
    'uglify',
    'copy',
    'requirejs',
    'rev',
    'usemin'
  ]);

  // CSS TASK
  grunt.registerTask('css', [
    'sass',
    'autoprefixer',
    'csslint'
  ]);

  // DEFAULT TASK
  grunt.registerTask('default', [
    'lint',
    'test',
    'build'
  ]);

  // LINT TASK
  grunt.registerTask('lint', [
    'jscs',
    'jshint',
    'copyright'
  ]);

  // SERVE TASK
  grunt.registerTask('serve', function (target) {
    if (target === 'dist') {
      return grunt.task.run(['build', 'open:server', 'connect:dist:keepalive']);
    }

    if (target === 'test') {
      return grunt.task.run([
        'clean:server',
        'connect:test',
        'open:test',
        'watch:livereload'
      ]);
    }

    grunt.task.run([
      'clean:server',
      'sass:dev',
      'autoprefixer',
      'connect:livereload',
      'open:server',
      'watch'
    ]);
  });

  // SERVER TASK
  grunt.registerTask('server', 'The `server` task has been deprecated. Use `grunt serve` to start a server.', function (target) {
    grunt.log.warn('The `server` task has been deprecated. Use `grunt serve` to start a server.');
    grunt.task.run(['serve:' + target]);
  });

  // TEST TASK
  grunt.registerTask('test', function (isConnected) {
    isConnected = Boolean(isConnected);
    var testTasks = [
      'clean:server'
    ];

    if (!isConnected) {
      return grunt.task.run(testTasks);
    } else {
      // already connected so not going to connect again, remove the connect:test task
      testTasks.splice(testTasks.indexOf('connect:test'), 1);
      return grunt.task.run(testTasks);
    }
  });
};
