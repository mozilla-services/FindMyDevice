/*global define*/

define([
  'views/base',
  'stache!templates/location'
], function (BaseView, LocationTemplate) {
  'use strict';

  var LocationView = BaseView.extend({
    template: LocationTemplate
  });

  return LocationView;
});
