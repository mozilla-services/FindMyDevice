/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'views/base',
  'stache!templates/erase_confirmation',
  'lib/modal_manager',
  'models/erase_command'
], function (BaseView, EraseConfirmationTemplate, ModalManager, EraseCommand) {
  'use strict';

  var EraseView = BaseView.extend({
    template: EraseConfirmationTemplate,

    events: {
      'click button.cancel': 'cancel',
      'click button.erase': 'erase'
    },

    initialize: function (options) {
      this.device = options.device;
    },

    cancel: function (event) {
      ModalManager.close();
    },

    erase: function (event) {
      this.device.sendCommand(new EraseCommand());

      // The location will no longer be accessible after erase
      this.device.set({ activity: 'erase', located: false });

      ModalManager.close();
    }
  });

  return EraseView;
});
