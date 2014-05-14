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
