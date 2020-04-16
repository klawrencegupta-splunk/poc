require('./EnableDisableToggle.pcss');

const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const keyboard = require('util/keyboard');

module.exports = Component.extend({
    name: 'EnableDisableToggle',

    moduleId: module.id,

    tagName: 'span',

    template:
        `<span data-enabled="<%= model.get(attribute) ? "true" : "false" %>">
            <% if (viewModel.get("pending")) { %>
                <% if (model.get(attribute)) { %>
                    <span disabled>Disable</span> | Enabled
                <% } else { %>
                    Disabled | <span disabled>Enable</span>
                <% } %>
            <% } else { %>
                <% if (model.get(attribute)) { %>
                    <a class="disable" tabindex="0"><%= _("Disable").t() %></a>
                    | <%= _("Enabled").t() %>
                <% } else { %>
                    <%= _("Disabled").t() %> 
                    | <a class="enable" tabindex="0"><%= _("Enable").t() %></a>
                <% } %>
            <% } %>
        </span>`,

    templateContext() {
        return {
            model: this.model,
            viewModel: this.viewModel,
            attribute: this.attribute,
        };
    },

    events: {
        'click .enable': 'enableToggle',
        'click .disable': 'disableToggle',
        'keydown .enable': function (e) {
            this.keydown(e, 'enableToggle');
        },
        'keydown .disable': function (e) {
            this.keydown(e, 'disableToggle');
        },
    },

    initialize(opt) {
        Component.prototype.initialize.apply(this, arguments);

        if (!opt.model) {
            throw new Error('Expected a model to watch');
        }

        if (!opt || !opt.attribute) {
            throw new Error('Expected an options argument with an attribute name to watch');
        }

        this.viewModel = new Model({
            pending: false,
        });

        this.attribute = opt.attribute;
        this.onEnabled = opt.onEnabled;
        this.onDisabled = opt.onDisabled;
    },

    keydown(event, eventToggle) {
        const keyCode = event.which;
        if (keyCode === keyboard.KEYS.ENTER && eventToggle) {
            this[eventToggle]();
        }
    },

    enableToggle() {
        this.viewModel.set('pending', true);
        this.onEnabled(() => {
            this.viewModel.set('pending', false);
        });
    },

    disableToggle() {
        this.viewModel.set('pending', true);
        this.onDisabled(() => {
            this.viewModel.set('pending', false);
        });
    },
});
