/*global define*/

define([
  'jquery',
  'backbone',
  'views/location'
], function ($, Backbone, LocationView) {
    'use strict';

    var Router = Backbone.Router.extend({
      routes: {
        '': 'showLocation'
      },

      showLocation: function() {
        this.setStage(new LocationView());
      },

      setStage: function(view) {
        $("#stage").html(view.render().el);
      }
    });

    // Return a singleton
    return new Router();
});
