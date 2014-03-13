/*global define*/

define([
  'underscore',
  'jquery'
], function (_, $) {
  'use strict';

  var ModalManager = {
    _views: [],

    push: function(view) {
      this._views.push(view);

      this._show();
    },

    pop: function() {
      var view = this._views.pop();

      if (view) {
        view.destroy();
      }

      if (this._views.length > 0) {
        this._show();
      } else {
        this._hide();
      }
    },

    close: function() {
      _.invoke(this._views, 'destroy');

      this._hide();
    },

    _show: function() {
      var view = _.last(this._views);
      var el = view ? view.render().el : null

      $('#modal').html(el).show();
    },

    _hide: function() {
      $('#modal').html('').hide();
    }
  }

  return ModalManager;
});
