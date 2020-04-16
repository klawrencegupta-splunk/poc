require('./AlertMessage.pcss');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');

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
const _super = Component;
module.exports = Component.extend({
    template: `
        <% if (model.get("message")) { %>
            <div class="alert alert-message alert-<%- model.get("type") %>">
                <i class="icon-alert"></i>
                <%= model.get("message") %>
            </div>
        <% } %>
    `,
    initialize(opt = {}) {
        _super.prototype.initialize.apply(this, arguments);

        if (!opt.messageService) {
            throw new Error('No MessageService provided');
        }

        this.model = new Model({
            message: '',
            type: '',
        });

        this.listenTo(opt.messageService, 'error', (message) => {
            this.model.set('message', message);
            this.model.set('type', 'error');
        });

        this.listenTo(opt.messageService, 'warning', (message) => {
            this.model.set('message', message);
            this.model.set('type', 'warning');
        });

        this.listenTo(opt.messageService, 'info', (message) => {
            this.model.set('message', message);
            this.model.set('type', 'info');
        });

        this.listenTo(opt.messageService, 'clear', () => {
            this.model.set('message', undefined);
            this.model.set('type', 'info');
        });
    },
});
