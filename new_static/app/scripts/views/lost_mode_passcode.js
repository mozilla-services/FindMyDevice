/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/lost_mode_passcode',
  'lib/modal_manager'
], function (BaseView, LostModePasscodeTemplate, ModalManager) {
  'use strict';

  var LostModePasscodeView = BaseView.extend({
    template: LostModePasscodeTemplate,

    events: {
      'click a.back': 'back',
      'click button.activate': 'activate'
    },

    initialize: function(options) {
      this.phoneNumber = options.phoneNumber;
      this.note = options.note;
    },

    back: function(event) {
      ModalManager.pop();
    },

    activate: function(event) {
      this.passcode = this.$('.passcode').val();

      alert('I FEEL SO ACTIVATED');
    }
  });

  return LostModePasscodeView;
});
