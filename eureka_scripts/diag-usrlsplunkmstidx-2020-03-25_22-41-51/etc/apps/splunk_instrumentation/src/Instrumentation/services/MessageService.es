const Backbone = require('backbone');
const _ = require('underscore');

const proto = _.extend({
    error(...args) {
        window.console.error.apply(window.console, ['ERROR'].concat(args));
        this.trigger.apply(this, ['error'].concat(args));
    },
    warn(...args) {
        window.console.warn.apply(window.console, ['WARNING'].concat(args));
        this.trigger.apply(this, ['warning'].concat(args));
    },
    info(...args) {
        window.console.log.apply(window.console, ['INFO'].concat(args));
        this.trigger.apply(this, ['info'].concat(args));
    },
    clear() {
        this.trigger('clear');
    },
}, Backbone.Events);

function MessageService() {}
MessageService.prototype = proto;
module.exports = MessageService;
