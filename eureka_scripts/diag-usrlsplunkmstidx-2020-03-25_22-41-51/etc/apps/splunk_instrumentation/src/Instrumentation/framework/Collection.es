const Backbone = require('backbone');
const _ = require('underscore');
const globalState = require('./globalState');
const Model = require('./Model');
const BaseCollection = require('collections/Base');

function Collection(...args) {
    Backbone.Collection.apply(this, args);
}

// Have to extend our object literal because getters & setters don't copy
// over as getters & setters. This ensures our `models` property descriptor
// intercepts all access to `this.model` from the Backbone core methods.
Collection.prototype = _.extend({
    get models() {
        if (globalState.subscribing) {
            globalState.subscription.push({ type: 'collection', target: this });
        }
        return this.__models__;
    },

    set models(value) {
        this.__models__ = value;
    },

    peek() {
        return this.__models__;
    },
}, BaseCollection.prototype);

// If you pass in pojo objects, make sure they're converted to
// the kind of Model that can register for subscriptions.
Collection.prototype.model = Model;

module.exports = Collection;
