const Component = require('splunk_instrumentation/Instrumentation/framework/Component');

/**
 * Adapts a plain View to work as a Component.
 * Essentially just wraps the view
 */
module.exports = Component.extend({
    template: '',
    initialize(opt) {
        this.options = opt || {};

        if (!this.options.view) {
            throw new Error(
                'Expected options argument to contain a view member containing the view we are' +
                'adapting'
            );
        }
        this.view = this.options.view;

        this.once('afterRender', () => {
            this.$el.append(this.view.render().$el);
            this.on('afterRender', function afterRender() {
                this.view.render();
            });
        });
    },
});
