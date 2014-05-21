/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

define([
  'underscore',
  'jquery'
], function (_, $) {
  'use strict';

  var ModalManager = {
    _views: [],

    open: function(view) {
      this._destroyViews();

      this.push(view);
    },

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
      this._destroyViews();

      this._hide();
    },

    _destroyViews: function() {
      _.invoke(this._views, 'destroy');

      this._views = [];
    },

    _show: function() {
      var view = _.last(this._views);

      view.render();
      // Force delegate events to fix an issue where restoring a previous view breaks event bindings
      view.delegateEvents();

      $('#modal').html(view.el).show();
    },

    _hide: function() {
      $('#modal').html('').hide();
    }
  };

  return ModalManager;
});
