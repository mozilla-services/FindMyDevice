/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/lost_mode_passcode',
  'lib/modal_manager',
  'models/lock_command'
], function (BaseView, LostModePasscodeTemplate, ModalManager, LockCommand) {
  'use strict';

  var LostModePasscodeView = BaseView.extend({
    template: LostModePasscodeTemplate,

    events: {
      'click a.back': 'back',
      'submit form': 'activate'
    },

    initialize: function(options) {
      this.phoneNumber = options.phoneNumber;
      this.note = options.note;
    },

    back: function(event) {
      ModalManager.pop();
    },

    activate: function(event) {
      event.preventDefault();

      this.passcode = this.$('.passcode').val();

      currentDevice.sendCommand(new LockCommand({ code: this.passcode, message: this.note }));

      ModalManager.close();
    }
  });

  return LostModePasscodeView;
});
