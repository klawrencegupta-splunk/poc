const Backbone = require('backbone');
const globalState = require('./globalState');

module.exports = Backbone.Model.extend({
    get(attr) {
        if (globalState.subscribing) {
            globalState.subscription.push({ type: 'model', target: this, attribute: attr });
        }
        return Backbone.Model.prototype.get.call(this, attr);
    },

    peek(attr) {
        return Backbone.Model.prototype.get.call(this, attr);
    },
});
