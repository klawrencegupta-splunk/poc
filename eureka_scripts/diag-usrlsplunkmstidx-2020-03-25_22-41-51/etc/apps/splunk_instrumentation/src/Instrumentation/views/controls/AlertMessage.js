var Component = require('Instrumentation/framework/Component'),
    style = require('./AlertMessage.pcss'),
    Model = require('Instrumentation/framework/Model');

/**
 * Usage:
 *
 * var messageAlert = new MessageAlert({ messageService: myMessageService });
 * messageAlert.render().appendTo($('.wherever-you-want'));
 *
 * myMessageService.error('Your error message');
 * myMessageService.warn('Your warning message');
 * myMessageService.info('Your info message');
 */
var _super = Component;
module.exports = Component.extend({
    template: '\
        <% if (model.get("message")) { %>\
            <div class="alert alert-message alert-<%- model.get("type") %>">\
                <i class="icon-alert"></i>\
                <%= model.get("message") %>\
            </div>\
        <% } %>\
    ',
    initialize: function (opt) {
        _super.prototype.initialize.apply(this, arguments);

        opt = opt || {};

        if (!opt.messageService) {
            throw new Error("No MessageService provided");
        }

        this.model = new Model({
            message: '',
            type: ''
        });

        this.listenTo(opt.messageService, 'error', function (message) {
            this.model.set('message', message);
            this.model.set('type', 'error')
        }.bind(this));

        this.listenTo(opt.messageService, 'warning', function (message) {
            this.model.set('message', message);
            this.model.set('type', 'warning')
        }.bind(this));

        this.listenTo(opt.messageService, 'info', function (message) {
            this.model.set('message', message);
            this.model.set('type', 'info')
        }.bind(this));

        this.listenTo(opt.messageService, 'clear', function (message) {
            this.model.set('message', undefined);
            this.model.set('type', 'info')
        }.bind(this));
    }
});
