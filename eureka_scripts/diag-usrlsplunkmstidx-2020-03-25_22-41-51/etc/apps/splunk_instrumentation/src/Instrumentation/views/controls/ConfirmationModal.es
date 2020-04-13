const $ = require('jquery');
const _ = require('underscore');
const View = require('splunk_instrumentation/Instrumentation/framework/View');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const Modal = require('views/shared/Modal');

module.exports = Modal.extend({
    name: 'ConfirmationModal',
    moduleId: module.id,
    titleTemplate: '',
    bodyTemplate: '',
    footerTemplate: '',
    cancelButtonSelector: undefined,
    confirmButtonSelector: undefined,

    // Child classes may override this to provide arguments to the templates they supply.
    // (i.e. titleTemplate, bodyTemplate, & footerTemplate).
    templateContext() {
        return {};
    },

    initialize(options = {}) {
        Modal.prototype.initialize.apply(this, arguments);
        _.bindAll(this, 'confirmListener', 'cancelListener');

        // Fallback from options, to prototype, to creating a component from a template
        // (the template could come from options, or the prototype as well).
        this.titleComponent = options.titleComponent || this.titleComponent || new Component({
            tagName: 'span',
            template: options.titleTemplate || this.titleTemplate,
            templateContext: this.templateContext.bind(this),
            components: this.components,
        });

        this.bodyComponent = options.bodyComponent || this.bodyComponent || new Component({
            template: options.bodyTemplate || this.bodyTemplate,
            templateContext: this.templateContext.bind(this),
            components: this.components,
        });

        this.footerComponent = options.footerComponent || this.footerComponent || new Component({
            template: options.footerTemplate || this.footerTemplate,
            templateContext: this.templateContext.bind(this),
            components: this.components,
        });

        this.cancelButtonSelector = options.cancelButtonSelector || this.cancelButtonSelector;
        this.confirmButtonSelector = options.confirmButtonSelector || this.confirmButtonSelector;
    },

    render() {
        if (this.$('> *').length === 0) {
            this.$el.append(Modal.TEMPLATE);
            this.$('.modal-title').append(this.titleComponent.render().$el);
            this.$(Modal.BODY_SELECTOR).append(this.bodyComponent.render().$el);
            this.$(Modal.FOOTER_SELECTOR).append(this.footerComponent.render().$el);
        }
        return this;
    },

    /**
     * Returns a Deferred that will resolve when the modal is confirmed,
     * or else it will reject.
     */
    show() {
        Modal.prototype.show.call(this);

        this.render();

        return new $.Deferred((deferred) => {
            this.deferred = deferred;
            if (this.cancelButtonSelector) {
                this.$el.on('click', this.cancelButtonSelector, this.cancelListener);
            }
            if (this.confirmButtonSelector) {
                this.$el.on('click', this.confirmButtonSelector, this.confirmListener);
            }
            this.listenTo(this, 'hidden', this.cancelListener);
        });
    },

    confirmListener() {
        this.stopListening();
        this.hide();
        this.deferred.resolve();
    },

    cancelListener() {
        this.stopListening();
        this.hide();
        this.deferred.reject();
    },

    stopListening() {
        View.prototype.stopListening.call(this);
        if (this.cancelButtonSelector) {
            this.$el.off('click', this.cancelButtonSelector, this.cancelListener);
        }
        if (this.confirmButtonSelector) {
            this.$el.off('click', this.confirmButtonSelector, this.confirmListener);
        }
    },
});
