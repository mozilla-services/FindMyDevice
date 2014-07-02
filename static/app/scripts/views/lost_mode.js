/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/lost_mode',
  'lib/modal_manager',
  'views/lost_mode_passcode',
  'models/lock_command'
], function (BaseView, LostModeTemplate, ModalManager, LostModePasscodeView, LockCommand) {
  'use strict';

  var LostModeView = BaseView.extend({
    template: LostModeTemplate,

    events: {
      'click .activate': 'activate',
      'click .next': 'next'
    },

    initialize: function (options) {
      this.device = options.device;
    },

    getContext: function () {
      return {
        note: this.note,
        hasPasscode: this.device.get('hasPasscode')
      };
    },

    activate: function (event) {
      event.preventDefault();

      this.note = this.$('.note').val();

      this.device.sendCommand(new LockCommand({ message: this.note }));

      this.device.set('activity', 'lost');

      ModalManager.close();
    },

    next: function (event) {
      event.preventDefault();

      this.note = this.$('.note').val();

      ModalManager.push(new LostModePasscodeView({ device: this.device, note: this.note }));
    }
  });

  return LostModeView;
});
