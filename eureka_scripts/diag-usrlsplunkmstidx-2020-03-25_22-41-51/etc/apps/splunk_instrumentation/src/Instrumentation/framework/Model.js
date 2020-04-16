var Backbone = require('backbone'),
    global_state = require('./global_state');

module.exports = Backbone.Model.extend({
    get: function (attr) {
        if (global_state.subscribing) {
            global_state.subscription.push({type: 'model', target: this, attribute: attr});
        }
        return Backbone.Model.prototype.get.call(this, attr);
    },

    peek: function () {
        return Backbone.Model.prototype.get.call(this, attr);
    }
});
