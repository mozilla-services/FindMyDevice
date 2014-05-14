/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*global define*/

define([
  'views/base',
  'stache!templates/play_sound'
], function (BaseView, PlaySoundTemplate) {
  'use strict';

  var PlaySoundView = BaseView.extend({
    template: PlaySoundTemplate
  });

  return PlaySoundView;
});
