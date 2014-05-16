/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*global define*/

define([
  'views/base',
  'stache!templates/lost_mode',
  'lib/modal_manager',
  'views/lost_mode_passcode'
], function (BaseView, LostModeTemplate, ModalManager, LostModePasscodeView) {
  'use strict';

  var LostModeView = BaseView.extend({
    template: LostModeTemplate,

    events: {
      'click button.next': 'next'
    },

    next: function(event) {
      var phoneNumber = this.$('.phone-number').val();
      var note = this.$('.note').val();

      ModalManager.push(new LostModePasscodeView({ phoneNumber: phoneNumber, note: note }));
    }
  });

  return LostModeView;
});
