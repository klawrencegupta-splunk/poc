var global_state = require('./global_state'),
    Backbone = require('backbone'),
    _ = require('underscore');

/**
 * VolatileExpression allows you to express a value in terms of Backbone Models and Collections,
 * and fires a change event when any Model attribute or Collection it depends on has changed.
 *
 * Features:
 * - Throttling
 *   + When the change event is fired, the expression stops listening for future change events
 *     until the expression has been re-evaluated (by calling the `evaluate`) function.
 * - Automatic Change Detection
 *   + VolatileExpression works with the Model and Collection subclasses in this framework
 *     that will register themselves as dependencies of the expression if accessed within
 *     an expression.
 * - Minimal Observed Event Set
 *   + The expression will only watch those Models and Collections that actually contributed
 *     to the value of the expression. If, for example, you have an `else` clause that reads
 *     several Models, but that path is never taken, you will not pay the cost of binding
 *     to those change events. The set of observed objects is updated each time the expression
 *     is re-evaluated.
 * - Disposability
 *   + You may call `dispose` on the expression at any time to remove all change listeners
 *     and stop being notified about changes.
 *
 * Example:
 *
 * ```JavaScript
 * var expression = new VolatileExpression(function () {
 *   // If any of these attributes changes, the change event will be triggered.
 *   return model.get('some').get('deep').get('attr');
 * });
 *
 * expression.on('change', function () {
 *   console.log('New value of expression is :' + expression.evaluate());
 *   expression.dispose();
 * });
 * ```
 *
 */
function VolatileExpression(fn) {
    this.fn = fn;
    this.notify = this.notify.bind(this);
}
_.extend(VolatileExpression.prototype, Backbone.Events, {
    evaluate: function () {
        this.stopListening();

        global_state.subscribing = true;
        global_state.subscription = [];

        var newValue = this.fn();

        global_state.subscription.forEach(function (sub) {
            if (sub.type == 'model') {
                this.listenTo(sub.target, 'change:' + sub.attribute, this.notify);
            } else if (sub.type == 'collection' ){
                this.listenTo(sub.target, 'add', this.notify);
                this.listenTo(sub.target, 'remove', this.notify);
                this.listenTo(sub.target, 'update', this.notify);
                this.listenTo(sub.target, 'sort', this.notify);
                this.listenTo(sub.target, 'reset', this.notify);
            } else {
                throw new Error('Unrecognized target type for expression dependency: ' + sub.type);
            }
        }.bind(this));

        global_state.subscribing = false;
        global_state.subscription = [];

        if (newValue !== this.value) {
            this.value = newValue;
            this.trigger('value', this.value);
        }
        return this.value;
    },
    notify: function () {
        this.stopListening();
        this.trigger('change');
    },
    dispose: function () {
        this.stopListening();
    }
});

module.exports = VolatileExpression;
