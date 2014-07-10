/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'parsley',
  'views/base',
  'stache!templates/lost_mode_passcode',
  'lib/modal_manager',
  'models/lock_command'
], function (Parsley, BaseView, LostModePasscodeTemplate, ModalManager, LockCommand) {
  'use strict';

  var LostModePasscodeView = BaseView.extend({
    template: LostModePasscodeTemplate,

    events: {
      'click a.back': 'back',
      'submit form': 'activate'
    },

    initialize: function (options) {
      this.device = options.device;
      this.note = options.note;
    },

    afterRender: function() {
      this.$('form').parsley();
    },

    back: function (event) {
      ModalManager.pop();
    },

    activate: function (event) {
      event.preventDefault();

      this.device.sendCommand(new LockCommand({ code: this.passcode2, message: this.note }));

      this.device.set('activity', 'lost');

      ModalManager.close();
    }
  });

  return LostModePasscodeView;
});
