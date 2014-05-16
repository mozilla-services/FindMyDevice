/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*global define,alert*/

define([
  'views/base',
  'stache!templates/lost_mode_passcode'
], function (BaseView, LostModePasscodeTemplate) {
  'use strict';

  var LostModePasscodeView = BaseView.extend({
    template: LostModePasscodeTemplate,

    events: {
      'click button.activate': 'activate'
    },

    initialize: function(options) {
      this.phoneNumber = options.phoneNumber;
      this.note = options.note;
    },

    activate: function(event) {
      this.passcode = this.$('.passcode').val();

      alert('I FEEL SO ACTIVATED');
    }
  });

  return LostModePasscodeView;
});
