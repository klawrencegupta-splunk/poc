var Backbone = require('backbone'),
    _ = require('underscore');

var proto = _.extend({
    error: function () {
        var args = Array.prototype.slice.call(arguments);
        console.error.apply(console, ['ERROR'].concat(args));
        this.trigger.apply(this, ['error'].concat(args));
    },
    warn: function () {
        var args = Array.prototype.slice.call(arguments);
        console.warn.apply(console, ['WARNING'].concat(args));
        this.trigger.apply(this, ['warning'].concat(args));
    },
    info: function () {
        var args = Array.prototype.slice.call(arguments);
        console.log.apply(console, ['INFO'].concat(args));
        this.trigger.apply(this, ['info'].concat(args));
    },
    clear: function () {
        this.trigger('clear');
    }
}, Backbone.Events);

function MessageService() {};
MessageService.prototype = proto;
module.exports = MessageService;
