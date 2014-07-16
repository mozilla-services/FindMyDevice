/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

 // Learn more about configuring this file at <https://github.com/theintern/intern/wiki/Configuring-Intern>.
// These default settings work OK for most people. The options that *must* be changed below are the
// packages, suites, excludeInstrumentation, and (if you want functional tests) functionalSuites.
define(['intern/lib/args'], function (args) {
  'use strict';

  return {
    // Find My Device configuration
    fmd: {
      url: args.fmdUrl || 'http://localhost:8000/',
      email: args.fmdEmail || 'fmd-functional-test-user@mailinator.com',
      password: args.fmdPassword || 'fmdfxa123',
      commandTimeout: args.fmdCommandTimeout ? parseInt(args.fmdCommandTimeout, 10) : 3000,
      fxaTimeout: args.fmdFxaTimeout ? parseInt(args.fmdFxaTimeout, 10) : 10000,
      notifierSleepTime: args.fmdNotifierSleepTime ? parseInt(args.fmdNotifierSleepTime, 10) : 100
    },

    // The port on which the instrumenting proxy will listen
    proxyPort: 9000,

    // A fully qualified URL to the Intern proxy
    proxyUrl: 'http://localhost:9000/',

    // Default desired capabilities for all environments. Individual capabilities can be overridden by any of the
    // specified browser environments in the `environments` array below as well. See
    // https://code.google.com/p/selenium/wiki/DesiredCapabilities for standard Selenium capabilities and
    // https://saucelabs.com/docs/additional-config#desired-capabilities for Sauce Labs capabilities.
    // Note that the `build` capability will be filled in with the current commit ID from the Travis CI environment
    // automatically
    capabilities: {
      'selenium-version': '2.41.0'
    },

    // Browsers to run integration testing against. Note that version numbers must be strings if used with Sauce
    // OnDemand. Options that will be permutated are browserName, version, platform, and platformVersion; any other
    // capabilities options specified for an environment will be copied as-is
    environments: [
      { browserName: 'firefox' }
    ],

    // Maximum number of simultaneous integration tests that should be executed on the remote WebDriver service
    maxConcurrency: 3,

    reporters: [ 'console' ],

    // Whether or not to start Sauce Connect before running tests
    useSauceConnect: false,

    // Functional test suite(s) to run in each browser once non-functional tests are completed
    functionalSuites: [
      'tests/functional/index',
      'tests/functional/ring',
      'tests/functional/lock',
      'tests/functional/erase'
    ],

    // A regular expression matching URLs to files that should not be included in code coverage analysis
    excludeInstrumentation: /^(?:tests|node_modules)\//
  };
});
