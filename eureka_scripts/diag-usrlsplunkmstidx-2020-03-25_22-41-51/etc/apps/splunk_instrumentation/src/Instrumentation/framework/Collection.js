var Backbone = require('backbone'),
    _ = require('underscore'),
    global_state = require('./global_state'),
    Model = require('./Model'),
    BaseCollection = require('collections/Base');

var Collection = function () {
    Backbone.Collection.apply(this, arguments);
};

// Have to extend our object literal because getters & setters don't copy
// over as getters & setters. This ensures our `models` property descriptor
// intercepts all access to `this.model` from the Backbone core methods.
Collection.prototype = _.extend({
    get models() {
        if (global_state.subscribing) {
            global_state.subscription.push({type: 'collection', target: this});
        }
        return this.__models__;
    },

    set models(value) {
        this.__models__ = value;
    },

    peek: function () {
        return this.__models__;
    }
}, BaseCollection.prototype);

// If you pass in pojo objects, make sure they're converted to
// the kind of Model that can register for subscriptions.
Collection.prototype.model = Model;

module.exports = Collection;
